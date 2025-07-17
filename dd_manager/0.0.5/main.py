#!/usr/bin/env python3

"""
DD GUI Manager - Graphical interface for creating disk and partition images
Requirements: PySide6, psutil
Installation: pip install PySide6 psutil
"""

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import QInputDialog
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QComboBox, QPushButton,
                               QLineEdit, QCheckBox, QSpinBox, QProgressBar, QTextEdit, QGroupBox, QFrame, QFileDialog, QMessageBox,
                               QScrollArea, QDialog, QDialogButtonBox)

try:
    import psutil
except ImportError:
    print("Error: psutil library required. Install with: pip install psutil")
    sys.exit(1)


@dataclass
class Partition:
    """Class representing a partition"""
    device: str
    mountpoint: str
    fstype: str
    size: int
    used: int
    free: int
    label: str = ""

    @property
    def size_gb(self) -> float:
        return self.size / (1024 ** 3)

    @property
    def used_gb(self) -> float:
        return self.used / (1024 ** 3)

    @property
    def usage_percent(self) -> float:
        return (self.used / self.size * 100) if self.size > 0 else 0

    @property
    def pretty_size(self) -> str:
        """Return size as string with unit, e.g., '500 MB' or '2.5 GB'"""
        gb = self.size / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.1f} GB"
        else:
            mb = self.size / (1024 ** 2)
            return f"{mb:.0f} MB"



@dataclass
class DriveInfo:
    """Drive information"""
    device: str
    model: str
    size: int
    partitions: List[Partition]

    @property
    def size_gb(self) -> float:
        return self.size / (1024 ** 3)


class SudoPasswordDialog(QDialog):
    """Dialog for entering sudo password"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Administrator Password Required")
        self.setModal(True)
        self.setFixedSize(400, 150)

        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("This operation requires administrator privileges.\nPlease enter your password:")
        layout.addWidget(info_label)

        # Password field
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter your password")
        layout.addWidget(self.password_edit)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

        # Focus on password field
        self.password_edit.setFocus()

    def get_password(self):
        return self.password_edit.text()


class DDWorkerThread(QThread):
    """Worker thread for DD operations"""

    progress_updated = Signal(int, str)  # progress percentage, status text
    operation_finished = Signal(bool, str)  # success, message
    log_message = Signal(str)

    def __init__(self, source_device, target_file, options, sudo_password=None, encryption_password=None):
        super().__init__()
        self.source_device = source_device
        self.target_file = target_file
        self.options = options
        self.sudo_password = sudo_password
        self.encryption_password = encryption_password  # Dodaj hasło szyfrowania
        self.should_cancel = False
        self.process = None
        self.source_size = 0

    def run(self):
        """Main worker thread function"""
        try:
            # Get device size first
            self.source_size = self.get_device_size()
            if self.source_size == 0:
                self.operation_finished.emit(False, "Could not determine source device size")
                return

            self.log_message.emit(f"Source device size: {self.source_size / (1024 ** 3):.2f} GB")

            # Build and execute command
            self.execute_dd_command()

        except Exception as e:
            self.operation_finished.emit(False, f"Error: {str(e)}")

    def get_device_size(self):
        """Get device size without sudo using lsblk"""
        try:
            cmd = ["lsblk", "-b", "-dn", "-o", "SIZE", self.source_device]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                size_str = result.stdout.strip()
                size = int(size_str)
                if size > 0:
                    return size
                else:
                    self.log_message.emit("Error: Got zero size from lsblk command")
            else:
                self.log_message.emit(f"Error: lsblk command failed with return code {result.returncode}")
                if result.stderr:
                    self.log_message.emit(f"Error details: {result.stderr}")

        except Exception as e:
            self.log_message.emit(f"Error getting device size: {str(e)}")

        return 0

    def execute_dd_command(self):
        """Execute the DD command with optional compression and encryption"""
        try:
            # Sprawdź czy openssl jest dostępny dla szyfrowania
            if self.options.get('encrypt', False):
                try:
                    subprocess.run(['openssl', 'version'], capture_output=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.operation_finished.emit(False, "OpenSSL not found. Please install OpenSSL for encryption support.")
                    return

            # Buduj komendę w zależności od opcji
            cmd_parts = []

            # Część DD
            if self.sudo_password:
                dd_cmd = f"echo '{self.sudo_password}' | sudo -S dd if={self.source_device} bs=1M status=progress"
            else:
                dd_cmd = f"dd if={self.source_device} bs=1M status=progress"

            cmd_parts.append(dd_cmd)

            # Opcjonalne szyfrowanie
            if self.options.get('encrypt', False) and self.encryption_password:
                # Używamy AES-256-CBC z PBKDF2
                encrypt_cmd = f"openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:'{self.encryption_password}'"
                cmd_parts.append(encrypt_cmd)

            # Opcjonalna kompresja
            if self.options.get('compress', False):
                cmd_parts.append("gzip -c")

            # Określ rozszerzenie pliku wyjściowego
            output_file = self.target_file
            if self.options.get('encrypt', False):
                output_file += ".enc"
            if self.options.get('compress', False):
                output_file += ".gz"

            # Przekierowanie do pliku
            cmd_parts.append(f"> {output_file}")

            # Połącz wszystkie części
            full_cmd = " 2>&1 | ".join(cmd_parts[:-1]) + f" {cmd_parts[-1]}"

            # Ukryj hasła w logach
            log_cmd = full_cmd
            if self.sudo_password:
                log_cmd = log_cmd.replace(self.sudo_password, "***")
            if self.encryption_password:
                log_cmd = log_cmd.replace(self.encryption_password, "***")

            self.log_message.emit(f"Executing: {log_cmd}")

            # Uruchom proces
            self.process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True, bufsize=1,
                                          universal_newlines=True)

            # Monitoruj postęp
            self.monitor_progress()

        except Exception as e:
            self.operation_finished.emit(False, f"Error executing command: {str(e)}")

    def monitor_progress(self):
        """Monitor DD progress"""
        try:
            while self.process and self.process.poll() is None:
                if self.should_cancel:
                    if self.process:
                        self.process.terminate()
                        time.sleep(1)
                        if self.process.poll() is None:
                            self.process.kill()
                    self.operation_finished.emit(False, "Operation cancelled by user")
                    return

                # Try to read output
                if self.process.stdout:
                    line = self.process.stdout.readline()
                    if line:
                        self.parse_dd_output(line.strip())

                time.sleep(0.1)

            # Process finished
            if self.process:
                returncode = self.process.returncode
                if returncode == 0:
                    self.progress_updated.emit(100, "Operation completed successfully!")

                    # Dodaj informacje o szyfrowania i kompresji w komunikacie
                    features = []
                    if self.options.get('encrypt', False):
                        features.append("encrypted")
                    if self.options.get('compress', False):
                        features.append("compressed")

                    if features:
                        message = f"Image created successfully! ({', '.join(features)})"
                    else:
                        message = "Image created successfully!"

                    self.operation_finished.emit(True, message)
                else:
                    self.operation_finished.emit(False, f"Operation failed with return code: {returncode}")

        except Exception as e:
            self.operation_finished.emit(False, f"Error monitoring progress: {str(e)}")

    def parse_dd_output(self, line):
        """Parse DD output for progress information"""
        try:
            # Look for progress lines like: "1234567890 bytes (1.2 GB) copied, 10 s, 123 MB/s"
            if "bytes" in line and "copied" in line:
                # Extract bytes copied
                match = re.search(r'(\d+) bytes', line)
                if match:
                    bytes_copied = int(match.group(1))
                    if self.source_size > 0:
                        progress = min(100, int((bytes_copied / self.source_size) * 100))

                        # Extract speed if available
                        speed_match = re.search(r'(\d+(?:\.\d+)?)\s*([KMG]?B/s)', line)
                        if speed_match:
                            speed = speed_match.group(1)
                            unit = speed_match.group(2)
                            status = f"Progress: {progress}% - Speed: {speed} {unit}"
                        else:
                            status = f"Progress: {progress}%"

                        self.progress_updated.emit(progress, status)

        except Exception as e:
            self.log_message.emit(f"Error parsing output: {str(e)}")

    def cancel(self):
        """Cancel the operation"""
        self.should_cancel = True


# Dodaj nową klasę dla dialogu hasła szyfrowania
class EncryptionPasswordDialog(QDialog):
    """Dialog for entering encryption password"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Encryption Password")
        self.setModal(True)
        self.setFixedSize(400, 200)

        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("Enter password for encryption:")
        layout.addWidget(info_label)

        # Password field
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Enter encryption password")
        layout.addWidget(self.password_edit)

        # Confirm password field
        confirm_label = QLabel("Confirm password:")
        layout.addWidget(confirm_label)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.setPlaceholderText("Confirm encryption password")
        layout.addWidget(self.confirm_edit)

        # Warning label
        warning_label = QLabel("⚠️ Warning: If you lose this password, you will NOT be able to recover your data!")
        warning_label.setStyleSheet("color: red; font-weight: bold;")
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

        # Focus on password field
        self.password_edit.setFocus()

    def accept(self):
        """Override accept to validate passwords match"""
        if self.password_edit.text() != self.confirm_edit.text():
            QMessageBox.warning(self, "Password Mismatch", "Passwords do not match!")
            return

        if len(self.password_edit.text()) < 6:
            QMessageBox.warning(self, "Weak Password", "Password must be at least 6 characters long!")
            return

        super().accept()

    def get_password(self):
        return self.password_edit.text()


# Zmodyfikuj metodę create_image w DDGUIManager
def create_image(self):
    """Create disk/partition image"""
    if not self.current_drive_widget:
        self.show_error("No drive selected")
        return

    selected_partitions = self.current_drive_widget.get_selected_partitions()
    if not selected_partitions:
        self.show_error("No partitions selected")
        return

    target_file = self.target_edit.text().strip()
    if not target_file:
        self.show_error("No target file specified")
        return

    # Check if target file already exists
    if os.path.exists(target_file):
        reply = QMessageBox.question(self, "File exists", f"File {target_file} already exists. Do you want to overwrite it?",
            QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.No:
            return

    # Get encryption password if encryption is enabled
    encryption_password = None
    if self.encrypt_check.isChecked():
        dialog = EncryptionPasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            encryption_password = dialog.get_password()
        else:
            self.log("Operation cancelled - no encryption password provided")
            return

    # Check if we need sudo and get password
    source_device = selected_partitions[0].device
    sudo_password = None

    # First try without sudo
    try:
        with open(source_device, 'rb') as f:
            f.read(1)
    except PermissionError:
        # Need sudo, ask for password
        self.log("Administrator privileges required for accessing block device")
        dialog = SudoPasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            sudo_password = dialog.get_password()
            # Verify the password works
            test_cmd = f"echo '{sudo_password}' | sudo -S -v 2>/dev/null"
            if subprocess.run(test_cmd, shell=True).returncode != 0:
                self.show_error("Invalid administrator password")
                return
        else:
            self.log("Operation cancelled - no password provided")
            return
    except Exception as e:
        self.show_error(f"Error accessing device: {str(e)}")
        return

    # Prepare options
    options = {
        'compress': self.compress_check.isChecked(),
        'encrypt': self.encrypt_check.isChecked(),
        'split': self.split_check.isChecked(),
        'split_size': self.split_size.value() if self.split_check.isChecked() else None
    }

    self.log(f"Starting image creation {source_device} -> {target_file}")
    if options['encrypt']:
        self.log("Encryption enabled (AES-256-CBC)")
    if options['compress']:
        self.log("Compression enabled (gzip)")

    # Create and start worker thread
    self.worker_thread = DDWorkerThread(source_device, target_file, options, sudo_password, encryption_password)

    # Connect signals
    self.worker_thread.progress_updated.connect(self.on_progress_updated)
    self.worker_thread.operation_finished.connect(self.on_operation_finished)
    self.worker_thread.log_message.connect(self.log)

    # Update UI
    self.create_btn.setEnabled(False)
    self.cancel_btn.setEnabled(True)
    self.progress_bar.setVisible(True)
    self.status_label.setVisible(True)
    self.progress_bar.setValue(0)

    # Start the thread
    self.worker_thread.start()


class PartitionWidget(QFrame):
    """Widget representing a partition"""
    clicked = Signal(object)

    def __init__(self, partition: Partition, parent=None):
        super().__init__(parent)
        self.partition = partition
        self.selected = False
        self.setupUI()

    def setupUI(self):
        self.setFrameStyle(QFrame.Box)
        self.setLineWidth(2)
        self.setMinimumHeight(60)
        self.setMaximumHeight(60)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Partition name
        device_label = QLabel(f"{self.partition.device}")
        device_label.setFont(QFont("Arial", 10, QFont.Bold))

        # Partition information
        info_text = f"{self.partition.fstype} | {self.partition.pretty_size}"
        if self.partition.label:
            info_text += f" | {self.partition.label}"
        info_label = QLabel(info_text)
        info_label.setFont(QFont("Arial", 8))

        # Usage bar
        usage_frame = QFrame()
        usage_frame.setFixedHeight(8)
        usage_frame.setStyleSheet(f"""
            QFrame {{
                background-color: #e0e0e0;
                border: 1px solid #ccc;
            }}
        """)

        layout.addWidget(device_label)
        layout.addWidget(info_label)
        layout.addWidget(usage_frame)

        self.setLayout(layout)
        self.updateStyle()

    def updateStyle(self):
        if self.selected:
            self.setStyleSheet("""
                PartitionWidget {
                    background-color: #4CAF50;
                    border: 2px solid #2196F3;
                }
                QLabel {
                    color: white;
                }
            """)
        else:
            self.setStyleSheet("""
                PartitionWidget {
                    background-color: #f5f5f5;
                    border: 1px solid #ccc;
                }
                PartitionWidget:hover {
                    background-color: #e8f5e8;
                    border: 1px solid #4CAF50;
                }
            """)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            # Usuwamy zmianę stanu selected z tego miejsca
            # Teraz tylko sygnalizujemy kliknięcie
            self.clicked.emit(self)

class DriveWidget(QWidget):
    """Widget representing a drive with partitions"""

    def __init__(self, drive: DriveInfo, parent=None):
        super().__init__(parent)
        self.drive = drive
        self.partition_widgets = []
        self.selected_partition_widget = None  # Dodajemy zmienną do śledzenia wybranej partycji
        self.setupUI()

    def setupUI(self):
        layout = QVBoxLayout()

        # Drive information
        drive_info = QGroupBox(f"Drive: {self.drive.device}")
        drive_info.setFont(QFont("Arial", 10, QFont.Bold))

        info_layout = QVBoxLayout()

        model_label = QLabel(f"Model: {self.drive.model}")
        size_label = QLabel(f"Size: {self.drive.size_gb:.1f} GB")

        info_layout.addWidget(model_label)
        info_layout.addWidget(size_label)
        drive_info.setLayout(info_layout)

        # Partitions
        partitions_group = QGroupBox("Partitions")
        partitions_layout = QVBoxLayout()

        if self.drive.partitions:
            for partition in self.drive.partitions:
                partition_widget = PartitionWidget(partition)
                partition_widget.clicked.connect(self.on_partition_clicked)
                self.partition_widgets.append(partition_widget)
                partitions_layout.addWidget(partition_widget)
        else:
            no_partitions_label = QLabel("No partitions found")
            no_partitions_label.setStyleSheet("color: #666; font-style: italic;")
            partitions_layout.addWidget(no_partitions_label)

        partitions_group.setLayout(partitions_layout)

        layout.addWidget(drive_info)
        layout.addWidget(partitions_group)
        layout.addStretch()

        self.setLayout(layout)

    def on_partition_clicked(self, partition_widget):
        """Handle partition click - allow only single selection"""
        # Jeśli kliknięto na już wybraną partycję, odznacz ją
        if self.selected_partition_widget == partition_widget:
            self.selected_partition_widget.selected = False
            self.selected_partition_widget.updateStyle()
            self.selected_partition_widget = None
        else:
            # Odznacz poprzednio wybraną partycję
            if self.selected_partition_widget:
                self.selected_partition_widget.selected = False
                self.selected_partition_widget.updateStyle()

            # Zaznacz nową partycję
            partition_widget.selected = True
            partition_widget.updateStyle()
            self.selected_partition_widget = partition_widget

    def get_selected_partitions(self) -> List[Partition]:
        """Returns list of selected partitions (max 1)"""
        if self.selected_partition_widget:
            return [self.selected_partition_widget.partition]
        return []


class SystemInfoCollector:
    """Class for collecting system information"""

    @staticmethod
    def get_block_devices() -> List[DriveInfo]:
        """Gets information about block devices"""
        drives = []

        try:
            # Try without sudo first
            cmd = ["lsblk", "-J", "-o", "NAME,SIZE,MODEL,FSTYPE,MOUNTPOINT,LABEL"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                data = json.loads(result.stdout)

                for device in data.get("blockdevices", []):
                    if device.get("name", "").startswith(("sd", "nvme", "mmcblk")):
                        drives.append(SystemInfoCollector._parse_device(device))

        except Exception as e:
            print(f"Error getting drive information: {e}")

        return drives

    @staticmethod
    def get_device_size_with_sudo(device_path: str, sudo_password: str = None) -> int:
        """Gets device size using blockdev command, with sudo if needed"""
        try:
            # Try without sudo first
            cmd = ["blockdev", "--getsize64", device_path]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return int(result.stdout.strip())

            # If failed, try with sudo
            if sudo_password:
                cmd = f"echo '{sudo_password}' | sudo -S blockdev --getsize64 {device_path}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return int(result.stdout.strip())

            raise Exception("Failed to get device size")

        except Exception as e:
            print(f"Error getting device size: {e}")
            return 0

    @staticmethod
    def _parse_device(device: Dict[str, Any]) -> DriveInfo:
        """Parse device information"""
        device_name = f"/dev/{device['name']}"
        model = device.get("model", "Unknown")
        size_str = device.get("size", "0B")

        # Size conversion
        size_bytes = SystemInfoCollector._parse_size(size_str)

        # Parse partitions
        partitions = []
        for child in device.get("children", []):
            partition = SystemInfoCollector._parse_partition(child)
            if partition:
                partitions.append(partition)

        return DriveInfo(device=device_name, model=model, size=size_bytes, partitions=partitions)

    @staticmethod
    def _parse_partition(partition_data: Dict[str, Any]) -> Optional[Partition]:
        """Parse partition information"""
        try:
            device = f"/dev/{partition_data['name']}"
            mountpoint = partition_data.get("mountpoint", "")
            fstype = partition_data.get("fstype", "")
            label = partition_data.get("label", "")

            # Get usage information
            size_str = partition_data.get("size", "0B")
            size = SystemInfoCollector._parse_size(size_str)

            used = free = 0
            if mountpoint:
                try:
                    usage = psutil.disk_usage(mountpoint)
                    used = usage.used
                    free = usage.free
                except:
                    pass


            return Partition(device=device, mountpoint=mountpoint, fstype=fstype, size=size, used=used, free=free, label=label)
        except Exception as e:
            print(f"Error parsing partition: {e}")
            return None

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Convert size string to bytes"""
        if not size_str:
            return 0

        size_str = size_str.upper()
        multipliers = {'B': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4}

        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    number = float(size_str[:-1])
                    return int(number * multiplier)
                except:
                    return 0

        try:
            return int(float(size_str))
        except:
            return 0


class DDGUIManager(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.drives = []
        self.current_drive_widget = None
        self.worker_thread = None
        self.setupUI()
        self.loadDrives()
        self.showMaximized()

    def setupUI(self):
        self.setWindowTitle("DD GUI Manager - Disk Image Creator v0.7.0-alpha.1")
        self.setMinimumSize(1000, 700)

        # Main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)

        # Main layout
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        # Top section - drive selection
        drive_group = QGroupBox("Source Drive Selection")
        drive_layout = QHBoxLayout()

        self.drive_combo = QComboBox()
        self.drive_combo.currentIndexChanged.connect(self.on_drive_changed)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.loadDrives)

        drive_layout.addWidget(QLabel("Drive:"))
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addWidget(refresh_btn)
        drive_layout.addStretch()

        drive_group.setLayout(drive_layout)

        # Middle section - partitions
        partitions_group = QGroupBox("Partitions")
        partitions_layout = QVBoxLayout()

        # Scroll area for partitions
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumHeight(300)

        self.partitions_container = QWidget()
        self.partitions_layout = QVBoxLayout(self.partitions_container)
        scroll_area.setWidget(self.partitions_container)

        partitions_layout.addWidget(scroll_area)
        partitions_group.setLayout(partitions_layout)

        # Bottom section - configuration
        config_group = QGroupBox("Image Configuration")
        config_layout = QGridLayout()

        # Target file
        config_layout.addWidget(QLabel("Target file:"), 0, 0)
        self.target_edit = QLineEdit()
        config_layout.addWidget(self.target_edit, 0, 1)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_target_file)
        config_layout.addWidget(browse_btn, 0, 2)

        # Options
        self.compress_check = QCheckBox("Compress image (gzip)")
        config_layout.addWidget(self.compress_check, 1, 0)

        self.encrypt_check = QCheckBox("Encrypt image")
        config_layout.addWidget(self.encrypt_check, 1, 1)

        # Split into fragments
        self.split_check = QCheckBox("Split into fragments")
        config_layout.addWidget(self.split_check, 2, 0)

        self.split_size = QSpinBox()
        self.split_size.setRange(1, 99999)
        self.split_size.setValue(4096)
        self.split_size.setSuffix(" MB")
        self.split_size.setEnabled(False)
        self.split_check.toggled.connect(self.split_size.setEnabled)
        config_layout.addWidget(self.split_size, 2, 1)

        config_group.setLayout(config_layout)

        # Action buttons
        action_group = QGroupBox("Actions")
        action_layout = QHBoxLayout()

        self.create_btn = QPushButton("Create Image")
        self.create_btn.clicked.connect(self.create_image)
        self.create_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_operation)
        self.cancel_btn.setEnabled(False)

        action_layout.addWidget(self.create_btn)
        action_layout.addWidget(self.cancel_btn)
        action_layout.addStretch()

        action_group.setLayout(action_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setVisible(False)

        # Log
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout()

        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setReadOnly(True)

        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)

        # Add everything to main layout
        main_layout.addWidget(drive_group)
        main_layout.addWidget(partitions_group)
        main_layout.addWidget(config_group)
        main_layout.addWidget(action_group)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)
        main_layout.addWidget(log_group)

        # Styling
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)

        self.log("Application started")

    def loadDrives(self):
        """Load drive information"""
        self.log("Getting drive information...")
        self.drives = SystemInfoCollector.get_block_devices()

        self.drive_combo.clear()
        for drive in self.drives:
            self.drive_combo.addItem(f"{drive.device} - {drive.model} ({drive.size_gb:.1f} GB)")

        self.log(f"Found {len(self.drives)} drives")

        if self.drives:
            self.on_drive_changed(0)

    def on_drive_changed(self, index):
        """Handle drive change"""
        if 0 <= index < len(self.drives):
            drive = self.drives[index]
            self.show_drive_partitions(drive)
            self.log(f"Selected drive: {drive.device}")

    def show_drive_partitions(self, drive: DriveInfo):
        """Show partitions of selected drive"""
        # Remove previous widgets
        for i in reversed(range(self.partitions_layout.count())):
            child = self.partitions_layout.itemAt(i).widget()
            if child:
                child.setParent(None)

        # Add new drive widget
        self.current_drive_widget = DriveWidget(drive)
        self.partitions_layout.addWidget(self.current_drive_widget)
        self.partitions_layout.addStretch()

    def browse_target_file(self):
        """Browse for target file"""
        filename, _ = QFileDialog.getSaveFileName(self, "Save image as...",
                                                  f"disk_image_{self.drive_combo.currentText().split()[0].replace('/', '_')}.img",
                                                  "Image files (*.img);;All files (*)")

        if filename:
            self.target_edit.setText(filename)

    def check_sudo_needed(self, device_path) -> bool:
        """Check if sudo is needed to access device"""
        try:
            # Try to open device for reading
            with open(device_path, 'rb') as f:
                f.read(1)
            return False
        except PermissionError:
            return True
        except Exception:
            return True

    def get_sudo_password(self) -> Optional[str]:
        """Get sudo password from user"""
        dialog = SudoPasswordDialog(self)
        if dialog.exec() == QDialog.Accepted:
            return dialog.get_password()
        return None

    def create_image(self):
        """Create disk/partition image"""
        if not self.current_drive_widget:
            self.show_error("No drive selected")
            return

        selected_partitions = self.current_drive_widget.get_selected_partitions()
        if not selected_partitions:
            self.show_error("No partitions selected")
            return

        target_file = self.target_edit.text().strip()
        if not target_file:
            self.show_error("No target file specified")
            return

        # Check if target file already exists
        if os.path.exists(target_file):
            reply = QMessageBox.question(self, "File exists", f"File {target_file} already exists. Do you want to overwrite it?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                return

        # Check if we need sudo and get password
        source_device = selected_partitions[0].device
        sudo_password = None

        # First try without sudo
        try:
            with open(source_device, 'rb') as f:
                f.read(1)
        except PermissionError:
            # Need sudo, ask for password
            self.log("Administrator privileges required for accessing block device")
            dialog = SudoPasswordDialog(self)
            if dialog.exec() == QDialog.Accepted:
                sudo_password = dialog.get_password()
                # Verify the password works
                test_cmd = f"echo '{sudo_password}' | sudo -S -v 2>/dev/null"
                if subprocess.run(test_cmd, shell=True).returncode != 0:
                    self.show_error("Invalid administrator password")
                    return
            else:
                self.log("Operation cancelled - no password provided")
                return
        except Exception as e:
            self.show_error(f"Error accessing device: {str(e)}")
            return

        # Prepare options
        options = {'compress': self.compress_check.isChecked(), 'encrypt': self.encrypt_check.isChecked(),
            'split': self.split_check.isChecked(), 'split_size': self.split_size.value() if self.split_check.isChecked() else None}

        self.log(f"Starting image creation {source_device} -> {target_file}")

        # Create and start worker thread
        self.worker_thread = DDWorkerThread(source_device, target_file, options, sudo_password)

        # Connect signals
        self.worker_thread.progress_updated.connect(self.on_progress_updated)
        self.worker_thread.operation_finished.connect(self.on_operation_finished)
        self.worker_thread.log_message.connect(self.log)

        # Update UI
        self.create_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.status_label.setVisible(True)
        self.progress_bar.setValue(0)

        # Start the thread
        self.worker_thread.start()

    def on_progress_updated(self, progress, status):
        """Handle progress updates"""
        self.progress_bar.setValue(progress)
        self.status_label.setText(status)

    def on_operation_finished(self, success, message):
        """Handle operation completion"""
        self.log(message)

        if success:
            self.show_info(message)
            self.progress_bar.setValue(100)
        else:
            self.show_error(message)

        self.reset_ui()

    def cancel_operation(self):
        """Cancel operation"""
        if self.worker_thread and self.worker_thread.isRunning():
            self.log("Cancelling operation...")
            self.worker_thread.cancel()
            self.worker_thread.wait(5000)  # Wait up to 5 seconds

            if self.worker_thread.isRunning():
                self.worker_thread.terminate()
                self.worker_thread.wait()

            self.reset_ui()

    def reset_ui(self):
        """Reset UI after operation"""
        self.create_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        self.worker_thread = None

    def log(self, message):
        """Add message to log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

        # Scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def show_error(self, message):
        """Show error message"""
        QMessageBox.critical(self, "Error", message)

    def show_info(self, message):
        """Show info message"""
        QMessageBox.information(self, "Information", message)

    def closeEvent(self, event):
        """Handle window close event"""
        if self.worker_thread and self.worker_thread.isRunning():
            reply = QMessageBox.question(self, "Operation in progress", "An operation is in progress. Do you want to cancel it and exit?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.worker_thread.cancel()
                self.worker_thread.wait(5000)  # Wait up to 5 seconds

                if self.worker_thread.isRunning():
                    self.worker_thread.terminate()
                    self.worker_thread.wait()

                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


def main():
    """Main function"""
    app = QApplication(sys.argv)

    # Ustaw styl
    app.setStyle('Fusion')

    # Jasna paleta
    from PySide6.QtGui import QPalette, QColor
    palette = QPalette()

    palette.setColor(QPalette.Window, QColor(245, 245, 245))  # Tło okien
    palette.setColor(QPalette.WindowText, Qt.black)  # Tekst na oknach
    palette.setColor(QPalette.Base, QColor(255, 255, 255))  # Tło pól edycyjnych
    palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))  # Alternatywne tło
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.black)
    palette.setColor(QPalette.Text, Qt.black)
    palette.setColor(QPalette.Button, QColor(240, 240, 240))  # Tło przycisków
    palette.setColor(QPalette.ButtonText, Qt.black)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(0, 122, 204))  # Linki
    palette.setColor(QPalette.Highlight, QColor(0, 122, 204))  # Podświetlenie
    palette.setColor(QPalette.HighlightedText, Qt.white)  # Tekst na podświetleniu

    app.setPalette(palette)

    # Informacja w konsoli
    print("DD GUI Manager - Running as regular user")
    print("Administrator privileges will be requested when needed")
    print("=" * 50)

    # Główne okno
    window = DDGUIManager()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
