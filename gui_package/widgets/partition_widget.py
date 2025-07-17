from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QFrame, QVBoxLayout, QLabel
from core.models import Partition


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
