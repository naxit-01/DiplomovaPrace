import base64

class DILITHIUM:
    def __init__(self):
        global generate_keypair, sign, verify
        from pqcrypto.sign.dilithium4 import generate_keypair, sign, verify
    
    def generate_keypair(self):
        # Alice generates a (public, secret) key pair
        public_key, secret_key = generate_keypair()
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return public_key, secret_key

    def sign(self, secret_key, message):
        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sign(secret_key, message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
        return signature

    def verify(self, public_key, message, signature):
        # Bob uses Alice's public key to validate her signature
        public_key = base64.b64decode(public_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        assert verify(public_key, message.encode('utf-8'), signature)
        return True
    
class FALCON:
    def __init__(self):
        global generate_keypair, sign, verify
        from pqcrypto.sign.falcon_1024 import generate_keypair, sign, verify
    
    def generate_keypair(self):
        # Alice generates a (public, secret) key pair
        public_key, secret_key = generate_keypair()
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return public_key, secret_key

    def sign(self, secret_key, message):
        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sign(secret_key, message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
        return signature

    def verify(self, public_key, message, signature):
        # Bob uses Alice's public key to validate her signature
        public_key = base64.b64decode(public_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        assert verify(public_key, message.encode('utf-8'), signature)
        return True
    
class SPHINCS:
    def __init__(self):
        global generate_keypair, sign, verify
        from pqcrypto.sign.sphincs_haraka_128f_robust import generate_keypair, sign, verify
    
    def generate_keypair(self):
        # Alice generates a (public, secret) key pair
        public_key, secret_key = generate_keypair()
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return public_key, secret_key

    def sign(self, secret_key, message):
        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sign(secret_key, message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
        return signature

    def verify(self, public_key, message, signature):
        # Bob uses Alice's public key to validate her signature
        public_key = base64.b64decode(public_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        assert verify(public_key, message.encode('utf-8'), signature)
        return True