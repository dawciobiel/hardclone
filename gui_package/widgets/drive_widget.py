from typing import List

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QWidget, QVBoxLayout, QGroupBox, QLabel
from core.models import DriveInfo
from core.models import Partition
from gui_package.widgets.partition_widget import PartitionWidget


class DriveWidget(QWidget):
    """Widget representing a drive with partitions"""

    def __init__(self, drive: DriveInfo, parent=None):
        super().__init__(parent)
        self.drive = drive
        self.partition_widgets = []
        self.selected_partition_widget = None
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
