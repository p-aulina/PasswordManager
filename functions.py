from pathlib import Path
import random
import string
import hashlib
from cryptography.fernet import Fernet

# file management
def file_exist(file):
    if not file.exists():
        file.touch()

# generating password
def generate_password():
    length = 18
    charList = string.ascii_letters + string.digits + string.punctuation
    password = []
    for i in range(length):
        password.append(random.choice(charList))
    
    return password

# encryption
key = Fernet.generate_key()
cipher = Fernet(key)
def encrypt_password(password):
    encrypted = cipher.encrypt(password.encode())
    return encrypted

# decryption
def decrypt_password(pass_encrypt):
    decrypted = cipher.decrypt(pass_encrypt).decode()
    return decrypted

# hashing
def hashing(password, hfile):
    result = hashlib.sha256(password.encode())
    result = result.hexdigest()
    with hfile.open(mode = "w") as file:
        file.write(result)
    return result

def check_hash(password, hfile):
    result = hashlib.sha256(password.encode())
    result = result.hexdigest()
    with hfile.open(mode = "r") as file:
        hashed = file.read()
    if hashed == result:
        return True
    else:
        return False


hash_file = Path("hash.txt")
pass_file = Path("pass.txt")
file_exist(hash_file)
file_exist(pass_file)

print(encrypt_password("abc"))
print(decrypt_password(encrypt_password("abc")))