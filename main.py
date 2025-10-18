from PyQt6.QtWidgets import (
    QApplication, 
    QMainWindow,
    QDialog,
    QLineEdit,
    QLabel,
    QMessageBox,
    QWidget, 
    QVBoxLayout, 
    QPushButton,
    QListWidget,
    QListWidgetItem
    )
import sys
import json
import functions
from password import Password
from pathlib import Path
from cryptography.fernet import Fernet

class AddPasswordDialog(QDialog):
    def __init__(self, cipher):
        super().__init__()
        self.cipher = cipher
        self.setWindowTitle("Add password")
        self.setFixedSize(400, 300)

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Domain")

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("URL")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")

        self.generate_pass = QPushButton("Generate password")
        self.generate_pass.clicked.connect(self.generate_new_pass)

        self.confirm = QPushButton("Confirm")
        self.confirm.clicked.connect(self.confirm_password)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Domain"))
        layout.addWidget(self.domain_input)
        layout.addWidget(QLabel("URL"))
        layout.addWidget(self.url_input)
        layout.addWidget(QLabel("Username"))
        layout.addWidget(self.username_input)
        layout.addWidget(QLabel("Password"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.generate_pass)
        layout.addWidget(self.confirm)

        self.setLayout(layout)

    def generate_new_pass(self):
        temp_password = Password("", "", "", self.cipher)
        self.password_input.setText(temp_password.gen_password)
    
    def confirm_password(self):
        domain = self.domain_input.text()
        url = self.url_input.text()
        username = self.username_input.text()
        password = self.password_input.text()

        if not all([domain, url, username, password]):
            QMessageBox.warning(self, "Error, insufficient data")
            return

        password_entry = Password(domain, url, username, self.cipher, password)
        self.data = password_entry.formating()
        functions.add_json(Path("pass.json"), self.data)

        self.accept()

    

class MainWindow(QMainWindow):
    def __init__(self, cipher):
        super().__init__()
        self.cipher = cipher
        self.setWindowTitle("Password Manager")
        self.setFixedSize(800, 600)

        self.add_password = QPushButton("Add password")
        self.add_password.clicked.connect(self.add_pass)

        self.label = QLabel("Your passwords")
        self.list_widget = QListWidget()

        self.list_widget.itemClicked.connect(self.show_password_for_item)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.add_password)

        container = QWidget()
        container.setLayout(layout)

        self.setCentralWidget(container)

        self.load_passwords()
    
    def add_pass(self):
        add_pass_window = AddPasswordDialog(self.cipher)
        if add_pass_window.exec() == QDialog.DialogCode.Accepted:
            add_pass_window.close()
            self.load_passwords()
    
    def load_passwords(self):
        jfile = Path("pass.json")
        if jfile.exists():
            try:
                with open(jfile, "r", encoding = "utf-8") as file:
                    data = json.load(file)
                self.list_widget.clear()
                for entry in data:
                    display_text = f"{entry['domain']} - {entry['username']}"
                    self.list_widget.addItem(display_text)
            except Exception as e:
                print("Error loading JSON file:", e)
        else:
            self.list_widget.addItem("No passwords saved")

    def show_password_for_item(self, item: QListWidgetItem):
        text = item.text()
        domain = text.split(" - ")[0]

        try:
            password = functions.decrypted_form_json(Path("pass.json"), domain, self.cipher)
            QMessageBox.information(self, "Decrypted password", f"Password for {domain}:\n\n{password}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not decrypt password:\n{e}")

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
    kfile = Path("key.key")
    if not kfile.exists():
        functions.generate_key(kfile)
    
    try:
        key = functions.load_key(kfile)
    except Exception as e:
        print("Error in loading key:", e)
        return
        
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
            window = MainWindow(cipher)
            window.show()

            sys.exit(app.exec())
        else:
            print("Password Manager closed.")

if __name__ == "__main__":
    main()