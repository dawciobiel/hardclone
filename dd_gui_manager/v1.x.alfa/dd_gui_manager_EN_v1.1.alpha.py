#!/usr/bin/env python3
"""
DD GUI Manager - GUI tool to create disk and partition images
Requires: PySide6, psutil
"""

import sys
import os
import subprocess
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QComboBox, QPushButton, QLineEdit, QCheckBox, QSpinBox, QProgressBar,
    QTextEdit, QGroupBox, QScrollArea, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont

try:
    import psutil
except ImportError:
    print("Error: psutil library is required. Install it with: pip install psutil")
    sys.exit(1)


@dataclass
class Partition:
    device: str
    mountpoint: str
    fstype: str
    size: int
    used: int
    free: int
    label: str = ""

    @property
    def size_gb(self):
        return self.size / (1024**3)


@dataclass
class DriveInfo:
    device: str
    model: str
    size: int
    partitions: List[Partition]

    @property
    def size_gb(self):
        return self.size / (1024**3)


class DDThread(QThread):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, source, target, compress, encrypt, split_size):
        super().__init__()
        self.source = source
        self.target = target
        self.compress = compress
        self.encrypt = encrypt
        self.split_size = split_size
        self.cancelled = False

    def run(self):
        try:
            cmd_parts = [f"dd if={self.source} bs=1M status=progress"]

            if self.compress:
                cmd_parts.append("gzip")

            if self.encrypt:
                cmd_parts.append("gpg -c")

            final_cmd = " | ".join(cmd_parts)

            if self.split_size:
                final_cmd += f" | split -b {self.split_size}M - {self.target}.part_"
            else:
                final_cmd += f" > {self.target}"

            process = subprocess.Popen(final_cmd, shell=True, stderr=subprocess.PIPE, text=True)

            while True:
                if self.cancelled:
                    process.terminate()
                    break
                line = process.stderr.readline()
                if not line:
                    break

            process.wait()

            if process.returncode == 0:
                self.finished.emit("Image created successfully.")
            else:
                self.error.emit("Error during image creation.")

        except Exception as e:
            self.error.emit(str(e))

    def cancel(self):
        self.cancelled = True


class DDGUIManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DD GUI Manager")
        self.setMinimumSize(900, 600)
        self.dd_thread = None
        self.setupUI()
        self.load_drives()

    def setupUI(self):
        font = QFont("Arial", 10)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # Source drive
        drive_group = QGroupBox("Select source drive")
        drive_layout = QHBoxLayout()
        self.drive_combo = QComboBox()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_drives)
        drive_layout.addWidget(QLabel("Drive:"))
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addWidget(refresh_btn)
        drive_group.setLayout(drive_layout)

        # Target file
        target_group = QGroupBox("Target image")
        target_layout = QHBoxLayout()
        self.target_edit = QLineEdit()
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_target)
        target_layout.addWidget(QLabel("File:"))
        target_layout.addWidget(self.target_edit)
        target_layout.addWidget(browse_btn)
        target_group.setLayout(target_layout)

        # Options
        options_group = QGroupBox("Options")
        options_layout = QGridLayout()
        self.compress_check = QCheckBox("Compress image (gzip)")
        self.encrypt_check = QCheckBox("Encrypt image (gpg -c)")
        self.split_check = QCheckBox("Split file")
        self.split_size_spin = QSpinBox()
        self.split_size_spin.setRange(1, 99999)
        self.split_size_spin.setValue(4096)
        self.split_size_spin.setSuffix(" MB")
        self.split_size_spin.setEnabled(False)
        self.split_check.toggled.connect(self.split_size_spin.setEnabled)
        options_layout.addWidget(self.compress_check, 0, 0)
        options_layout.addWidget(self.encrypt_check, 0, 1)
        options_layout.addWidget(self.split_check, 1, 0)
        options_layout.addWidget(self.split_size_spin, 1, 1)
        options_group.setLayout(options_layout)

        # Action buttons
        action_layout = QHBoxLayout()
        self.create_btn = QPushButton("Create image")
        self.create_btn.clicked.connect(self.create_image)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_image)
        action_layout.addWidget(self.create_btn)
        action_layout.addWidget(self.cancel_btn)
        action_layout.addStretch()

        # Log
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)

        # Add to main layout
        main_layout.addWidget(drive_group)
        main_layout.addWidget(target_group)
        main_layout.addWidget(options_group)
        main_layout.addLayout(action_layout)
        main_layout.addWidget(QLabel("Log:"))
        main_layout.addWidget(self.log_text)

        # Dark theme
        self.setStyleSheet("""
            QWidget { background-color: #2b2b2b; color: #dcdcdc; }
            QPushButton { background-color: #3c3f41; border: 1px solid #555; padding: 5px; }
            QPushButton:hover { background-color: #505357; }
            QLineEdit, QComboBox, QTextEdit, QSpinBox { background-color: #3c3f41; border: 1px solid #555; }
            QGroupBox { border: 1px solid #555; margin-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
        """)

    def log(self, msg):
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {msg}")

    def load_drives(self):
        self.log("Loading drives...")
        self.drive_combo.clear()
        drives = self.get_block_devices()
        for d in drives:
            self.drive_combo.addItem(f"{d.device} - {d.model} ({d.size_gb:.1f} GB)")
        if drives:
            self.log(f"Found {len(drives)} drives.")
        else:
            self.log("No drives found.")

    def browse_target(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save image as...", "disk_image.img", "All files (*)")
        if filename:
            self.target_edit.setText(filename)

    def create_image(self):
        drive_text = self.drive_combo.currentText()
        if not drive_text:
            QMessageBox.warning(self, "Warning", "No drive selected.")
            return
        source = drive_text.split()[0]
        target = self.target_edit.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "No target file selected.")
            return

        compress = self.compress_check.isChecked()
        encrypt = self.encrypt_check.isChecked()
        split = self.split_check.isChecked()
        split_size = self.split_size_spin.value() if split else None

        self.dd_thread = DDThread(source, target, compress, encrypt, split_size)
        self.dd_thread.finished.connect(self.on_finished)
        self.dd_thread.error.connect(self.on_error)
        self.dd_thread.start()
        self.log(f"Started imaging: {source} -> {target}")
        self.create_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

    def cancel_image(self):
        if self.dd_thread:
            self.dd_thread.cancel()
            self.log("Operation canceled.")
            self.dd_thread = None
            self.create_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)

    def on_finished(self, msg):
        self.log(msg)
        self.create_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def on_error(self, msg):
        self.log(f"Error: {msg}")
        self.create_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def get_block_devices(self) -> List[DriveInfo]:
        drives = []
        try:
            cmd = ["lsblk", "-J", "-o", "NAME,SIZE,MODEL"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            data = json.loads(result.stdout)
            for dev in data.get("blockdevices", []):
                if dev.get("name", "").startswith(("sd", "nvme", "mmcblk")):
                    device_name = f"/dev/{dev['name']}"
                    size = self._parse_size(dev.get("size", "0B"))
                    drives.append(DriveInfo(device=device_name, model=dev.get("model", ""), size=size, partitions=[]))
        except Exception as e:
            self.log(f"Failed to list devices: {e}")
        return drives

    def _parse_size(self, size_str):
        if not size_str:
            return 0
        size_str = size_str.upper()
        multipliers = {'B': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-1]) * mult)
                except:
                    return 0
        return 0


def main():
    app = QApplication(sys.argv)
    window = DDGUIManager()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
