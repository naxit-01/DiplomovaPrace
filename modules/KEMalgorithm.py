import base64

class PQCRYPTO:
    def __init__(self):
        global generate_keypair, encrypt, decrypt
        from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
        

    def generate_keypair(self):
        public_key, secret_key = generate_keypair()
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return public_key, secret_key
    
    def encrypt(self, public_key):
        public_key = base64.b64decode(public_key.encode('utf-8'))
        ciphertext, symmetrickey_original = encrypt(public_key)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        symmetrickey_original = base64.b64encode(symmetrickey_original).decode('utf-8')
        return ciphertext, symmetrickey_original
    
    def decrypt(self,secret_key,ciphertext):
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        symmetrickey_recovered = decrypt(secret_key, ciphertext)
        symmetrickey_recovered = base64.b64encode(symmetrickey_recovered).decode('utf-8')
        return symmetrickey_recovered

class KYBERPY:
    def __init__(self):
        global Kyber512
        from kyberpy.kyber import Kyber512

    def generate_keypair(self):
        public_key, secret_key = Kyber512.keygen() #generuje privatni s shared klice
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return public_key, secret_key
    
    def encrypt(self, public_key):
        public_key = base64.b64decode(public_key.encode('utf-8'))
        ciphertext, symmetrickey_original = Kyber512.enc(public_key)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        symmetrickey_original = base64.b64encode(symmetrickey_original).decode('utf-8') 
        return ciphertext, symmetrickey_original
    
    def decrypt(self,secret_key,ciphertext):
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        symmetrickey_recovered = Kyber512.dec(ciphertext,secret_key)
        symmetrickey_recovered = base64.b64encode(symmetrickey_recovered).decode('utf-8')
        return symmetrickey_recovered