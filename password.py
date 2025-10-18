import random
import string
import base64

class Password:
    length = 18
    def __init__(self, domain, url, username, cipher, password = None):
        self.domain = domain
        self.url = url
        self.username = username
        self.cipher = cipher

        if password:
            self.gen_password = password
        else:
            self.gen_password = self.generate_password()

        self.encrypted = self.encrypt_password(self.gen_password, self.cipher)
        
    
    # generating password
    def generate_password(self):
        charList = string.ascii_letters + string.digits + string.punctuation
        password = []
        for i in range(self.length):
            password.append(random.choice(charList))
        return "".join(password)
    
    # encryption
    def encrypt_password(self, password, cipher):
        encrypted = cipher.encrypt(password.encode())
        self.encrypted = encrypted
        return base64.b64encode(encrypted).decode("utf-8")
    
    # .json data format
    def formating(self):
        return {
            "domain" : self.domain,
            "url" : self.url,
            "username" : self.username,
            "encrypted" : self.encrypted
        }
    

    