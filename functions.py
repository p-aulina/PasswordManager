from pathlib import Path
import password
import hashlib
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import json
import base64
import os

#key
def generate_key(file: Path):
    key = Fernet.generate_key()
    with open(file, "wb") as kfile:
        kfile.write(key)
    
    try:
        os.chmod(file, 0o600)
    except Exception:
        pass

def load_key(file: Path) -> bytes:
    if not file.exists():
        raise FileNotFoundError(f"Key file not found: {file}")
    
    key = file.read_bytes()
    if not isinstance(key, (bytes, bytearray)) or len(key) != 44:
        raise ValueError("Invalid Fernet key (unexpected length or format)")
    
    return bytes(key)

# file management
def file_exist(file):
    if not file.exists():
        file.touch()

def start_json(jfile):
    p = []
    with jfile.open(mode = "w", encoding = "utf-8") as file:
        json.dump(p, file, indent = 4, ensure_ascii = False)

def add_json(jfile, password):
    data = []

    if jfile.exists() and jfile.stat().st_size > 0:
        try:
            data = json.loads(jfile.read_text(encoding = "utf-8"))
        except json.JDONDecodeError:
            print("JSON file is damaged or empty.")
    data.append(password)
    jfile.write_text(json.dumps(data, indent = 4, ensure_ascii = False), encoding = "utf-8")

def delete_from_json(jfile: Path, domain_to_delete: str, username_to_delete: str):
    if not jfile.exists() or jfile.stat().st_size == 0:
        return False

    try:
        with open(jfile, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Filtrujemy dane — zostawiamy tylko te, które NIE pasują do podanego domain+username
        new_data = [
            entry for entry in data
            if not (entry["domain"] == domain_to_delete and entry["username"] == username_to_delete)
        ]

        with open(jfile, "w", encoding="utf-8") as file:
            json.dump(new_data, file, indent=4, ensure_ascii=False)

        return True
    except Exception as e:
        print("Error deleting password:", e)
        return False


# hashing
def hashing(password, hfile):
    result = hashlib.sha256(password.encode())
    result = result.hexdigest()
    with hfile.open(mode = "w") as file:
        file.write(result)

def check_hash(password, hfile):
    result = hashlib.sha256(password.encode())
    result = result.hexdigest()
    with hfile.open(mode = "r") as file:
        hashed = file.read()
    if hashed == result:
        return True
    else:
        return False
    
# decryption
def decrypt_password(pass_encrypt, cipher):
    try:
        encrypted_bytes = base64.b64decode(pass_encrypt)
        decrypted = cipher.decrypt(encrypted_bytes).decode("utf-8")
        return decrypted
    except (InvalidToken, ValueError, base64.binascii.Error) as e:
        raise ValueError("Nie można odszyfrować hasła: " + str(e))

def decrypted_form_json(jfile, domain, cipher):
    with jfile.open(mode = "r", encoding = "utf-8") as file:
        data = json.load(file)
    for entry in data:
        if entry.get("domain") == domain:
            encrypted_pass = entry.get("encrypted")
            if encrypted_pass:
                return decrypt_password(encrypted_pass, cipher)
    raise ValueError(f"No password for domain: {domain}")

def get_url(jfile, domain):
    with jfile.open(mode = "r", encoding = "utf-8") as file:
        data = json.load(file)
    for entry in data:
        if entry.get("domain") == domain:
            url = entry.get("url")
            return url
    raise ValueError(f"No url for domain: {domain}")


# p = password.Password("Instagram", "http://instagram.com", cipher)
# add_json(pass_file, p.formating())
# print(decrypted_form_json(pass_file, "Instagram"))

# password = password.Password("gmail.com", "https://gmail.com", cipher)
# print(password.gen_password, "\n")
# print(password.encrypted, "\n")
# print(decrypt_password(password.encrypted))