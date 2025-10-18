from pathlib import Path
import password
import random
import string
import hashlib
from cryptography.fernet import Fernet
import json

# file management
def file_exist(file):
    if not file.exists():
        file.touch()

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
    decrypted = cipher.decrypt(pass_encrypt).decode()
    return decrypted

key = Fernet.generate_key()
cipher = Fernet(key)
hash_file = Path("hash.txt")
pass_file = Path("pass.json")
file_exist(hash_file)
file_exist(pass_file)

password = password.Password("gmail.com", "https://gmail.com", cipher)
print(password.gen_password, "\n")
print(password.encrypted, "\n")
print(decrypt_password(password.encrypted))