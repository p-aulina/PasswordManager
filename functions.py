from pathlib import Path
import password
import hashlib
from cryptography.fernet import Fernet
import json
import base64

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

# hashing
def hashing(password, hfile):
    result = hashlib.sha256(password.encode())
    result = result.hexdigest()
    with hfile.open(mode = "w") as file:
        file.write(result)
    key = Fernet.generate_key()
    cipher = Fernet(key)
    return result, cipher

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
def decrypt_password(pass_encrypt):
    encrypted_bytes = base64.b64decode(pass_encrypt)
    decrypted = cipher.decrypt(encrypted_bytes).decode()
    return decrypted

def decrypted_form_json(jfile, domain):
    with jfile.open(mode = "r", encoding = "utf-8") as file:
        data = json.load(file)
    for entry in data:
        if entry.get("domain") == domain:
            encrypted_pass = entry.get("encrypted")
            if encrypted_pass:
                return decrypt_password(encrypted_pass)
    raise ValueError(f"No password for domain: {domain}")
 
key = Fernet.generate_key()
cipher = Fernet(key)
hash_file = Path("hash.txt")
pass_file = Path("pass.json")
file_exist(hash_file)
file_exist(pass_file)

# p = password.Password("Instagram", "http://instagram.com", cipher)
# add_json(pass_file, p.formating())
# print(decrypted_form_json(pass_file, "Instagram"))

# password = password.Password("gmail.com", "https://gmail.com", cipher)
# print(password.gen_password, "\n")
# print(password.encrypted, "\n")
# print(decrypt_password(password.encrypted))