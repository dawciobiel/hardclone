from PySide6.QtWidgets import QDialog, QLineEdit, QLabel, QVBoxLayout, QDialogButtonBox, QMessageBox


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
