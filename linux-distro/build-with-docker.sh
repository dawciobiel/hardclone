#!/bin/bash
# build-with-docker.sh - Skrypt budowania archiso z Docker

set -e

# Kolory dla output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Budowanie Imaging Distribution z Docker ===${NC}"

# Sprawdź czy Docker jest dostępny
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker nie jest zainstalowany!${NC}"
    exit 1
fi

# Utwórz katalog projektu
PROJECT_DIR="$(pwd)/imaging-distro"
mkdir -p "$PROJECT_DIR"

echo -e "${YELLOW}Tworzenie kontenera Docker...${NC}"

# Buduj obraz Docker
docker build -t archiso-builder . 2>/dev/null || {
    echo -e "${YELLOW}Budowanie obrazu Docker z Dockerfile...${NC}"
    cat > Dockerfile << 'EOF'
FROM archlinux:latest

# Aktualizacja i instalacja niezbędnych pakietów
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm archiso git base-devel && \
    pacman -Scc --noconfirm

# Utwórz katalog roboczy
WORKDIR /build

# Skopiuj profil archiso
RUN cp -r /usr/share/archiso/configs/releng ./my-imaging-distro

# Ustaw katalog roboczy na nasz profil
WORKDIR /build/my-imaging-distro

# Domyślna komenda
CMD ["bash"]
EOF
    
    docker build -t archiso-builder .
}

echo -e "${GREEN}Uruchamianie kontenera...${NC}"

# Uruchom kontener z montowanym katalogiem
docker run -it --rm \
    --privileged \
    -v "$PROJECT_DIR":/output \
    archiso-builder bash -c "
    
    echo '=== Konfiguracja archiso ==='
    
    # Modyfikuj packages.x86_64
    cat >> packages.x86_64 << 'PACKAGES_EOF'

# Dodatkowe narzędzia obrazowania
ddrescue
clonezilla
partclone
fsarchiver
testdisk
# safecopy

# Narzędzia dyskowe
util-linux
gparted
grub

# Narzędzia szyfrowania
cryptsetup
gnupg
openssl

# Narzędzia sieciowe
samba
cifs-utils
vsftpd
# pure-ftpd
nfs-utils
lighttpd
konsole

# Edytory i narzędzia
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

# Programowanie
python3-pyside6


# Minimal GUI
xorg-server
xorg-xinit
fluxbox
xterm
firefox
thunar

# Systemy plików
btrfs-progs
xfsprogs
f2fs-tools
nilfs-utils

# Narzędzia diagnostyczne
smartmontools
hdparm
lshw
PACKAGES_EOF

    echo '=== Tworzenie katalogów ==='
    mkdir -p airootfs/etc/systemd/system
    mkdir -p airootfs/usr/local/bin
    mkdir -p airootfs/etc/ssh
    mkdir -p airootfs/etc/samba
    
    echo '=== Tworzenie skryptów ==='
    
    # Skrypt SSH setup
    cat > airootfs/usr/local/bin/setup-ssh.sh << 'SSH_EOF'
#!/bin/bash
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi
if [ ! -f /etc/ssh/.root_password_set ]; then
    echo \"root:imaging\" | chpasswd
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
echo \"Password: imaging\"
echo \"IP Address: \$(hostname -I | awk '{print \$1}')\"
echo \"Connect: ssh root@\$(hostname -I | awk '{print \$1}')\"
echo \"========================\"
SSH_EOF
    
    chmod +x airootfs/usr/local/bin/setup-ssh.sh
    
    # Konfiguracja SSH
    cat > airootfs/etc/ssh/sshd_config << 'SSHD_EOF'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
X11Forwarding yes
PrintMotd no
UseDNS no
SSHD_EOF
    
    # Systemd service dla SSH
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
    
    # Główny skrypt narzędzi
    cat > airootfs/usr/local/bin/imaging-tools.sh << 'TOOLS_EOF'
#!/bin/bash
echo \"=== Narzędzia Obrazowania ===\"
echo \"1. Wyświetl dyski\"
echo \"2. Utwórz obraz dysku (dd)\"
echo \"3. Utwórz obraz z kompresją\"
echo \"4. Sprawdź stan dysków\"
echo \"0. Wyjście\"
read -p \"Wybierz opcję: \" choice
case \$choice in
    1) lsblk -f ;;
    2) 
        echo \"Dostępne dyski:\"
        lsblk -d -o NAME,SIZE,MODEL
        read -p \"Podaj dysk źródłowy (np. /dev/sda): \" source
        read -p \"Podaj ścieżkę docelową: \" target
        dd if=\"\$source\" of=\"\$target\" bs=4M status=progress
        ;;
    3)
        echo \"Dostępne dyski:\"
        lsblk -d -o NAME,SIZE,MODEL
        read -p \"Podaj dysk źródłowy (np. /dev/sda): \" source
        read -p \"Podaj ścieżkę docelową (.gz): \" target
        dd if=\"\$source\" bs=4M status=progress | gzip -c > \"\$target\"
        ;;
    4) smartctl -H /dev/sda ;;
    0) exit 0 ;;
esac
TOOLS_EOF
    
    chmod +x airootfs/usr/local/bin/imaging-tools.sh
    
    # Włącz auto-ssh service
    ln -sf /etc/systemd/system/auto-ssh.service airootfs/etc/systemd/system/multi-user.target.wants/auto-ssh.service
    
    echo '=== Budowanie ISO ==='
    
    # Buduj ISO
    mkarchiso -v -w /tmp/work -o /output .
    
    echo '=== Gotowe! ==='
    echo \"ISO zostało utworzone w katalogu: /output\"
    ls -la /output/
    "

echo -e "${GREEN}=== Budowanie zakończone! ===${NC}"
echo -e "${YELLOW}Sprawdź katalog: $PROJECT_DIR${NC}"
echo -e "${YELLOW}Plik ISO powinien być gotowy do użycia.${NC}"
