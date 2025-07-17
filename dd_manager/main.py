
"""
DD GUI Manager - Graphical interface for creating disk and partition images
Requirements: PySide6, psutil
Installation: pip install -r requirements.txt
"""

import sys

try:
    import psutil
except ImportError:
    print("Error: psutil library required. Install with: pip install psutil")
    sys.exit(1)

import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt
from gui import DDGUIManager


def main():
    """Main function"""
    app = QApplication(sys.argv)

    # Ustaw styl
    app.setStyle('Fusion')

    # Jasna paleta
    from PySide6.QtGui import QPalette, QColor
    palette = QPalette()

    palette.setColor(QPalette.Window, QColor(245, 245, 245))  # Window background
    palette.setColor(QPalette.WindowText, Qt.black)  # Text on the windows
    palette.setColor(QPalette.Base, QColor(255, 255, 255))  # Background of editing fields
    palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))  # Alternative background
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.black)
    palette.setColor(QPalette.Text, Qt.black)
    palette.setColor(QPalette.Button, QColor(240, 240, 240))  # Buttons background
    palette.setColor(QPalette.ButtonText, Qt.black)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(0, 122, 204))  # Links
    palette.setColor(QPalette.Highlight, QColor(0, 122, 204))  # Backlight
    palette.setColor(QPalette.HighlightedText, Qt.white)  # Backlight text

    app.setPalette(palette)

    # Information in the console
    print("DD GUI Manager - Running as regular user")
    print("Administrator privileges will be requested when needed")
    print("=" * 50)

    # Główne okno
    window = DDGUIManager()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
