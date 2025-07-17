import os
import subprocess
from typing import Optional

from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QComboBox, QPushButton, QLineEdit, \
    QCheckBox, QSpinBox, QProgressBar, QTextEdit, QGroupBox, QFileDialog, QMessageBox, QScrollArea, QDialog

from gui_package.dialogs import SudoPasswordDialog, EncryptionPasswordDialog
from core.models import DriveInfo
from core.system_info import SystemInfoCollector
from gui_package.widgets.drive_widget import DriveWidget
from workers import DDWorkerThread


class DDGUIManager(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.version = self.load_version()
        self.drives = []
        self.current_drive_widget = None
        self.worker_thread = None
        self.setupUI()
        self.loadDrives()
        self.showMaximized()

    def load_version(self) -> str:
        try:
            with open("VERSION", "r") as f:
                return f.read().strip()
        except Exception:
            return "unknown"

    def setupUI(self):
        self.setWindowTitle(f"DD GUI Manager - Disk Image Creator v{self.version}")
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
        """Show partitions of the selected drive"""
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
        selected_partition_list = self.current_drive_widget.get_selected_partitions()
        selected_partition_name = selected_partition_list[0].device.replace('/', '_')
        # old_selected_partition_name =  self.drive_combo.currentText().split()[0].replace('/', '_')

        filename, _ = QFileDialog.getSaveFileName(self, "Save image as...", f"disk_image_{selected_partition_name}.img",
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
        options = {'compress': self.compress_check.isChecked(), 'encrypt': self.encrypt_check.isChecked(),
                   'split': self.split_check.isChecked(), 'split_size': self.split_size.value() if self.split_check.isChecked() else None}

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
