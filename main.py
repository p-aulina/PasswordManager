from PyQt6.QtWidgets import (
    QApplication, 
    QMainWindow,
    QDialog,
    QLineEdit,
    QLabel,
    QMessageBox,
    QWidget, 
    QVBoxLayout, 
    QPushButton
    )
import sys
import functions
import password
from pathlib import Path
from cryptography.fernet import Fernet

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.resize(800, 600)

class LoginDialog(QDialog):
    def check_password(self):
            if functions.check_hash(self.password_input.text(), Path("hash.txt")) == True:
                self.accept()
            else:
                QMessageBox.warning(self, "Error", "Incorrect password.")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Log in")
        self.setFixedSize(300, 150)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")

        self.login_button = QPushButton("Log in")
        self.login_button.clicked.connect(self.check_password)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter your password:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

class SetMainPasswordDialog(QDialog):
    def set_password(self):
        if self.password_input.text() == self.password_confirm.text():
            functions.hashing(self.password_input.text(), Path("hash.txt"))
            self.accept()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Set password")
        self.setFixedSize(300, 150)
        self.password_input = QLineEdit()
        self.password_confirm = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_confirm.setPlaceholderText("Confirm your password")

        self.set_password_putton = QPushButton("Set password")
        self.set_password_putton.clicked.connect(self.set_password)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Set main password to your Manager:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.password_confirm)
        layout.addWidget(self.set_password_putton)

        self.setLayout(layout)

def main():
    key = Fernet.generate_key()
    cipher = Fernet(key)
    hash_file = Path("hash.txt")
    pass_file = Path("pass.json")
    functions.file_exist(hash_file)
    functions.file_exist(pass_file)

    app = QApplication(sys.argv)

    if hash_file.stat().st_size == 0:
        set_pass = SetMainPasswordDialog()
        if set_pass.exec() == QDialog.DialogCode.Accepted:
            set_pass.close()

    if hash_file.stat().st_size > 0:
        login = LoginDialog()
        if login.exec() == QDialog.DialogCode.Accepted:
            window = QMainWindow()
            window.show()

            sys.exit(app.exec())
        else:
            print("Password Manager closed.")

if __name__ == "__main__":
    main()