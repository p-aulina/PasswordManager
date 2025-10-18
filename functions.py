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

# 

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
file_exist(hash_file)
print(hashing("abc", hash_file))
p = input()
print(check_hash(p, hash_file))