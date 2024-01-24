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
        return "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----", "-----BEGIN SECRET KEY-----\n" + secret_key + "\n-----END SECRET KEY-----"


    def sign(self, secret_key, message):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        secret_key_start = "-----BEGIN SECRET KEY-----"
        secret_key_end = "-----END SECRET KEY-----"

        # Získání klíče
        secret_key = secret_key.split(secret_key_start)[1].split(secret_key_end)[0].strip()

        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sign(secret_key, message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
        #return signature

        return "-----BEGIN SIGNATURE-----\n" + signature + "\n-----END SIGNATURE-----"

    def verify(self, public_key, message, signature):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        public_key_start = "-----BEGIN PUBLIC KEY-----"
        public_key_end = "-----END PUBLIC KEY-----"

        # Získání klíče
        public_key = public_key.split(public_key_start)[1].split(public_key_end)[0].strip()

        # Oddělení záhlaví a závěrky a získání samotného klíče
        signature_start = "-----BEGIN SIGNATURE-----"
        signature_end = "-----END SIGNATURE-----"

        # Získání klíče
        signature = signature.split(signature_start)[1].split(signature_end)[0].strip()

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
        #return public_key, secret_key
        return "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----", "-----BEGIN SECRET KEY-----\n" + secret_key + "\n-----END SECRET KEY-----"

    def sign(self, secret_key, message):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        secret_key_start = "-----BEGIN SECRET KEY-----"
        secret_key_end = "-----END SECRET KEY-----"

        # Získání klíče
        secret_key = secret_key.split(secret_key_start)[1].split(secret_key_end)[0].strip()

        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sign(secret_key, message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
        #return signature
        return "-----BEGIN SIGNATURE-----\n" + signature + "\n-----END SIGNATURE-----"

    def verify(self, public_key, message, signature):

        # Oddělení záhlaví a závěrky a získání samotného klíče
        public_key_start = "-----BEGIN PUBLIC KEY-----"
        public_key_end = "-----END PUBLIC KEY-----"

        # Získání klíče
        public_key = public_key.split(public_key_start)[1].split(public_key_end)[0].strip()

        # Oddělení záhlaví a závěrky a získání samotného klíče
        signature_start = "-----BEGIN SIGNATURE-----"
        signature_end = "-----END SIGNATURE-----"

        # Získání klíče
        signature = signature.split(signature_start)[1].split(signature_end)[0].strip()

        # Bob uses Alice's public key to validate her signature
        public_key = base64.b64decode(public_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        assert verify(public_key, message.encode('utf-8'), signature)
        return True