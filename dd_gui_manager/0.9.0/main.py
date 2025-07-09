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



import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor
from gui import DDGUIManager

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
