import random
import string
import base64

class Password:
    length = 18
    def __init__(self, domain, url, cipher):
        self.domain = domain
        self.url = url
        self.cipher = cipher
        self.gen_password = self.generate_password()
        self.encrypted = self.encrypt_password(self.gen_password, self.cipher)
    
    # generating password
    def generate_password(self):
        charList = string.ascii_letters + string.digits + string.punctuation
        password = []
        for i in range(self.length):
            password.append(random.choice(charList))
        print("".join(password))
        return "".join(password)
    
    # encryption
    def encrypt_password(self, password, cipher):
        encrypted = cipher.encrypt(password.encode())
        # print("Encrypted \n", encrypted)
        return base64.b64encode(encrypted).decode("utf-8")
    
    # .json data format
    def formating(self):
        return {
            "domain" : self.domain,
            "url" : self.url,
            "encrypted" : self.encrypted
        }
    

    