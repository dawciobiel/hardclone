#!/bin/bash
# build-with-docker.sh - Script to build Arch ISO with Docker

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo -e "${GREEN}=== Building Imaging Distribution with Docker ===${NC}"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed!${NC}"
    exit 1
fi

# Create project directory
PROJECT_DIR="$(pwd)/imaging-distro"
mkdir -p "$PROJECT_DIR"

echo -e "${YELLOW}Creating Docker container...${NC}"

# Build Docker image
docker build -t archiso-builder . 2>/dev/null || {
    echo -e "${YELLOW}Building Docker image from Dockerfile...${NC}"
    cat > Dockerfile << 'EOF'
FROM archlinux:latest

# Update and install required packages
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm archiso git base-devel && \
    pacman -Scc --noconfirm

# Create working directory
WORKDIR /build

# Copy default archiso profile
RUN cp -r /usr/share/archiso/configs/releng ./my-imaging-distro

WORKDIR /build/my-imaging-distro

CMD ["bash"]
EOF

    docker build -t archiso-builder .
}

echo -e "${GREEN}Running container...${NC}"

# Run container with mounted output directory
docker run -it --rm \
    --privileged \
    -v "$PROJECT_DIR":/output \
    archiso-builder bash -c "

    echo '=== Configuring archiso ==='

    # Append packages to packages.x86_64
    cat >> packages.x86_64 << 'PACKAGES_EOF'

# Imaging tools
ddrescue
clonezilla
partclone
fsarchiver
testdisk

# Disk tools
util-linux
gparted
grub

# Encryption tools
cryptsetup
gnupg
openssl

# Networking tools
samba
cifs-utils
vsftpd
nfs-utils
lighttpd
konsole

# Editors and utilities
neovim
mc
fish
duf
tree
tmux
htop
glances
irssi
screen

# Development
pyside6
jdk-openjdk

# Minimal GUI (KDE Plasma)
plasma-desktop
plasma-workspace
sddm
dolphin
xorg-server
xorg-xinit
xterm
firefox

# File systems
btrfs-progs
xfsprogs
f2fs-tools
nilfs-utils

# Diagnostic tools
smartmontools
hdparm
lshw
PACKAGES_EOF

    echo '=== Creating required directories ==='
    mkdir -p airootfs/etc/systemd/system
    mkdir -p airootfs/usr/local/bin
    mkdir -p airootfs/etc/ssh
    mkdir -p airootfs/etc/samba
    mkdir -p airootfs/etc/systemd/system/multi-user.target.wants

    echo '=== Creating scripts ==='

    # SSH setup script
    cat > airootfs/usr/local/bin/setup-ssh.sh << 'SSH_EOF'
#!/bin/bash
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi
if [ ! -f /etc/ssh/.root_password_set ]; then
    echo \"root:hardclone\" | chpasswd
    touch /etc/ssh/.root_password_set
fi
mkdir -p /root/.ssh
chmod 700 /root/.ssh
systemctl enable sshd
systemctl start sshd
echo \"=== SSH Server Started ===\"
echo \"SSH Server: ACTIVE\"
echo \"Port: 22\"
echo \"Root login: YES\"
echo \"Password: hardclone\"
echo \"IP Address: \$(hostname -I | awk '{print \$1}')\"
echo \"Connect: ssh root@\$(hostname -I | awk '{print \$1}')\"
SSH_EOF

    chmod +x airootfs/usr/local/bin/setup-ssh.sh

    # SSH configuration
    cat > airootfs/etc/ssh/sshd_config << 'SSHD_EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
X11Forwarding yes
PrintMotd no
UseDNS no
SSHD_EOF

    # Systemd service for SSH auto-start
    cat > airootfs/etc/systemd/system/auto-ssh.service << 'SERVICE_EOF'
[Unit]
Description=Auto-start SSH server
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-ssh.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    # Main imaging tools script
    cat > airootfs/usr/local/bin/imaging-tools.sh << 'TOOLS_EOF'
#!/bin/bash
echo \"=== Imaging Tools ===\"
echo \"1. Show disks\"
echo \"2. Create disk image (dd)\"
echo \"3. Create compressed image\"
echo \"4. Check disk health\"
echo \"0. Exit\"
read -p \"Choose option: \" choice
case \$choice in
    1) lsblk -f ;;
    2)
        echo \"Available disks:\"
        lsblk -d -o NAME,SIZE,MODEL
        read -p \"Source disk (e.g. /dev/sda): \" source
        read -p \"Destination path: \" target
        dd if=\"\$source\" of=\"\$target\" bs=4M status=progress
        ;;
    3)
        echo \"Available disks:\"
        lsblk -d -o NAME,SIZE,MODEL
        read -p \"Source disk (e.g. /dev/sda): \" source
        read -p \"Destination file (.gz): \" target
        dd if=\"\$source\" bs=4M status=progress | gzip -c > \"\$target\"
        ;;
    4) smartctl -H /dev/sda ;;
    0) exit 0 ;;
    *) echo \"Invalid option!\" ;;
esac
TOOLS_EOF

    chmod +x airootfs/usr/local/bin/imaging-tools.sh

    # Enable SSH auto-start service
    ln -sf /etc/systemd/system/auto-ssh.service airootfs/etc/systemd/system/multi-user.target.wants/auto-ssh.service

    echo '=== Building ISO ==='
    mkarchiso -v -w /tmp/work -o /output .

    echo '=== Done! ==='
    echo \"ISO created in /output:\"
    ls -la /output/
    "

echo ""
echo -e "${GREEN}=== Build finished! ===${NC}"
echo -e "${YELLOW}Check directory: $PROJECT_DIR${NC}"
echo -e "${YELLOW}ISO file should be ready to use.${NC}"
echo ""
