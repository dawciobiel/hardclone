#!/usr/bin/env python3
"""
build_archiso.py - Python script to build Arch ISO with Docker
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import json
import logging
from typing import List, Dict, Optional
import argparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

class ArchISOBuilder:
    def __init__(self, project_name: str = "imaging-distro"):
        self.project_name = project_name
        self.project_dir = Path.cwd() / project_name
        self.docker_image = "archiso-builder"
        
        # Package lists organized by category
        self.packages = {
            "imaging_tools": [
                "ddrescue", "clonezilla", "partclone", "fsarchiver", "testdisk"
            ],
            "disk_tools": [
                "util-linux", "gparted", "grub"
            ],
            "encryption_tools": [
                "cryptsetup", "gnupg", "openssl"
            ],
            "networking_tools": [
                "samba", "cifs-utils", "vsftpd", "nfs-utils", "lighttpd", "konsole"
            ],
            "editors_utilities": [
                "neovim", "mc", "fish", "duf", "tree", "tmux", "htop", "glances", "irssi", "screen"
            ],
            "development": [
                "pyside6", "jdk-openjdk"
            ],
            "gui_kde": [
                "plasma-desktop", "plasma-workspace", "sddm", "dolphin", 
                "xorg-server", "xorg-xinit", "xterm", "firefox"
            ],
            "filesystems": [
                "btrfs-progs", "xfsprogs", "f2fs-tools", "nilfs-utils"
            ],
            "diagnostic_tools": [
                "smartmontools", "hdparm", "lshw"
            ]
        }
        
        self.scripts = {
            "ssh_setup": self._get_ssh_setup_script(),
            "imaging_tools": self._get_imaging_tools_script(),
            "sshd_config": self._get_sshd_config(),
            "systemd_service": self._get_systemd_service()
        }

    def print_colored(self, message: str, color: str = Colors.NC) -> None:
        """Print colored message"""
        print(f"{color}{message}{Colors.NC}")

    def check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            subprocess.run(["docker", "--version"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def create_project_directory(self) -> None:
        """Create project directory"""
        self.project_dir.mkdir(exist_ok=True)
        logger.info(f"Created project directory: {self.project_dir}")

    def get_dockerfile_content(self) -> str:
        """Get Dockerfile content"""
        return '''FROM archlinux:latest

# Update and install required packages
RUN pacman -Syu --noconfirm && \\
    pacman -S --noconfirm archiso git base-devel && \\
    pacman -Scc --noconfirm

# Create working directory
WORKDIR /build

# Copy default archiso profile
RUN cp -r /usr/share/archiso/configs/releng ./my-imaging-distro

WORKDIR /build/my-imaging-distro

CMD ["bash"]
'''

    def build_docker_image(self) -> bool:
        """Build Docker image"""
        try:
            # Try to use existing image
            result = subprocess.run(
                ["docker", "build", "-t", self.docker_image, "."],
                capture_output=True, check=False
            )
            
            if result.returncode != 0:
                self.print_colored("Building Docker image from Dockerfile...", Colors.YELLOW)
                
                # Create Dockerfile
                dockerfile_path = Path("Dockerfile")
                dockerfile_path.write_text(self.get_dockerfile_content())
                
                # Build image
                subprocess.run(
                    ["docker", "build", "-t", self.docker_image, "."],
                    check=True
                )
                
                # Clean up
                dockerfile_path.unlink()
                
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build Docker image: {e}")
            return False

    def get_packages_list(self) -> List[str]:
        """Get flat list of all packages"""
        all_packages = []
        for category, packages in self.packages.items():
            all_packages.extend(packages)
        return all_packages

    def generate_packages_content(self) -> str:
        """Generate packages.x86_64 content"""
        content = []
        for category, packages in self.packages.items():
            content.append(f"\n# {category.replace('_', ' ').title()}")
            content.extend(packages)
        return "\n".join(content)

    def _get_ssh_setup_script(self) -> str:
        """Get SSH setup script content"""
        return '''#!/bin/bash
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -A
fi
if [ ! -f /etc/ssh/.root_password_set ]; then
    echo "root:hardclone" | chpasswd
    touch /etc/ssh/.root_password_set
fi
mkdir -p /root/.ssh
chmod 700 /root/.ssh
systemctl enable sshd
systemctl start sshd
echo "=== SSH Server Started ==="
echo "SSH Server: ACTIVE"
echo "Port: 22"
echo "Root login: YES"
echo "Password: hardclone"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "Connect: ssh root@$(hostname -I | awk '{print $1}')"
'''

    def _get_imaging_tools_script(self) -> str:
        """Get imaging tools script content"""
        return '''#!/bin/bash
echo "=== Imaging Tools ==="
echo "1. Show disks"
echo "2. Create disk image (dd)"
echo "3. Create compressed image"
echo "4. Check disk health"
echo "0. Exit"
read -p "Choose option: " choice
case $choice in
    1) lsblk -f ;;
    2)
        echo "Available disks:"
        lsblk -d -o NAME,SIZE,MODEL
        read -p "Source disk (e.g. /dev/sda): " source
        read -p "Destination path: " target
        dd if="$source" of="$target" bs=4M status=progress
        ;;
    3)
        echo "Available disks:"
        lsblk -d -o NAME,SIZE,MODEL
        read -p "Source disk (e.g. /dev/sda): " source
        read -p "Destination file (.gz): " target
        dd if="$source" bs=4M status=progress | gzip -c > "$target"
        ;;
    4) smartctl -H /dev/sda ;;
    0) exit 0 ;;
    *) echo "Invalid option!" ;;
esac
'''

    def _get_sshd_config(self) -> str:
        """Get SSH daemon configuration"""
        return '''Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
X11Forwarding yes
PrintMotd no
UseDNS no
'''

    def _get_systemd_service(self) -> str:
        """Get systemd service configuration"""
        return '''[Unit]
Description=Auto-start SSH server
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-ssh.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
'''

    def generate_build_commands(self) -> str:
        """Generate build commands for Docker container"""
        packages_content = self.generate_packages_content()
        
        commands = f'''
echo "=== Configuring archiso ==="

# Append packages to packages.x86_64
cat >> packages.x86_64 << 'PACKAGES_EOF'
{packages_content}
PACKAGES_EOF

echo "=== Creating required directories ==="
mkdir -p airootfs/etc/systemd/system
mkdir -p airootfs/usr/local/bin
mkdir -p airootfs/etc/ssh
mkdir -p airootfs/etc/samba
mkdir -p airootfs/etc/systemd/system/multi-user.target.wants

echo "=== Creating scripts ==="

# SSH setup script
cat > airootfs/usr/local/bin/setup-ssh.sh << 'SSH_EOF'
{self.scripts['ssh_setup']}SSH_EOF

chmod +x airootfs/usr/local/bin/setup-ssh.sh

# SSH configuration
cat > airootfs/etc/ssh/sshd_config << 'SSHD_EOF'
{self.scripts['sshd_config']}SSHD_EOF

# Systemd service for SSH auto-start
cat > airootfs/etc/systemd/system/auto-ssh.service << 'SERVICE_EOF'
{self.scripts['systemd_service']}SERVICE_EOF

# Main imaging tools script
cat > airootfs/usr/local/bin/imaging-tools.sh << 'TOOLS_EOF'
{self.scripts['imaging_tools']}TOOLS_EOF

chmod +x airootfs/usr/local/bin/imaging-tools.sh

# Enable SSH auto-start service
ln -sf /etc/systemd/system/auto-ssh.service airootfs/etc/systemd/system/multi-user.target.wants/auto-ssh.service

echo "=== Building ISO ==="
mkarchiso -v -w /tmp/work -o /output .

echo "=== Done! ==="
echo "ISO created in /output:"
ls -la /output/
'''
        return commands

    def run_build(self) -> bool:
        """Run the build process"""
        try:
            build_commands = self.generate_build_commands()
            
            cmd = [
                "docker", "run", "-it", "--rm",
                "--privileged",
                "-v", f"{self.project_dir}:/output",
                self.docker_image,
                "bash", "-c", build_commands
            ]
            
            self.print_colored("Running container...", Colors.GREEN)
            result = subprocess.run(cmd, check=True)
            
            return result.returncode == 0
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Build failed: {e}")
            return False

    def list_packages(self) -> None:
        """List all packages by category"""
        self.print_colored("\n=== Package List ===", Colors.BLUE)
        for category, packages in self.packages.items():
            self.print_colored(f"\n{category.replace('_', ' ').title()}:", Colors.YELLOW)
            for package in packages:
                print(f"  - {package}")

    def add_package(self, category: str, package: str) -> None:
        """Add a package to specific category"""
        if category not in self.packages:
            self.packages[category] = []
        
        if package not in self.packages[category]:
            self.packages[category].append(package)
            logger.info(f"Added package '{package}' to category '{category}'")
        else:
            logger.warning(f"Package '{package}' already exists in category '{category}'")

    def remove_package(self, package: str) -> None:
        """Remove a package from all categories"""
        removed = False
        for category, packages in self.packages.items():
            if package in packages:
                packages.remove(package)
                logger.info(f"Removed package '{package}' from category '{category}'")
                removed = True
        
        if not removed:
            logger.warning(f"Package '{package}' not found in any category")

    def save_config(self, filepath: str) -> None:
        """Save current configuration to JSON file"""
        config = {
            "project_name": self.project_name,
            "packages": self.packages
        }
        
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration saved to {filepath}")

    def load_config(self, filepath: str) -> None:
        """Load configuration from JSON file"""
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
            
            self.project_name = config.get("project_name", self.project_name)
            self.packages = config.get("packages", self.packages)
            
            logger.info(f"Configuration loaded from {filepath}")
            
        except FileNotFoundError:
            logger.error(f"Configuration file {filepath} not found")
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file {filepath}")

    def build(self) -> bool:
        """Main build process"""
        self.print_colored("\n=== Building Imaging Distribution with Docker ===", Colors.GREEN)
        
        # Check Docker
        if not self.check_docker():
            self.print_colored("Docker is not installed!", Colors.RED)
            return False
        
        # Create project directory
        self.create_project_directory()
        
        # Build Docker image
        self.print_colored("Creating Docker container...", Colors.YELLOW)
        if not self.build_docker_image():
            return False
        
        # Run build
        success = self.run_build()
        
        if success:
            self.print_colored("\n=== Build finished! ===", Colors.GREEN)
            self.print_colored(f"Check directory: {self.project_dir}", Colors.YELLOW)
            self.print_colored("ISO file should be ready to use.", Colors.YELLOW)
        else:
            self.print_colored("\n=== Build failed! ===", Colors.RED)
        
        return success


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Build Arch ISO with Docker")
    parser.add_argument("--project-name", default="imaging-distro", 
                       help="Project name (default: imaging-distro)")
    parser.add_argument("--list-packages", action="store_true",
                       help="List all packages by category")
    parser.add_argument("--add-package", nargs=2, metavar=("CATEGORY", "PACKAGE"),
                       help="Add a package to specific category")
    parser.add_argument("--remove-package", metavar="PACKAGE",
                       help="Remove a package from all categories")
    parser.add_argument("--save-config", metavar="FILE",
                       help="Save configuration to JSON file")
    parser.add_argument("--load-config", metavar="FILE",
                       help="Load configuration from JSON file")
    parser.add_argument("--build", action="store_true", default=True,
                       help="Build the ISO (default action)")
    
    args = parser.parse_args()
    
    builder = ArchISOBuilder(args.project_name)
    
    # Load config if specified
    if args.load_config:
        builder.load_config(args.load_config)
    
    # Handle package management
    if args.add_package:
        category, package = args.add_package
        builder.add_package(category, package)
    
    if args.remove_package:
        builder.remove_package(args.remove_package)
    
    # List packages if requested
    if args.list_packages:
        builder.list_packages()
        return
    
    # Save config if specified
    if args.save_config:
        builder.save_config(args.save_config)
    
    # Build ISO
    if args.build or len(sys.argv) == 1:
        success = builder.build()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()