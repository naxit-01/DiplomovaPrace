import base64

class PQCRYPTO:
    def __init__(self, version):
        global generate_keypair, encrypt, decrypt
        #from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
        if version == "Kyber512":
            from pqcryptoL.pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
        elif version == "Kyber512_90s":
            from pqcryptoL.pqcrypto.kem.kyber512_90s import generate_keypair, encrypt, decrypt
        elif version == "Kyber768":
            from pqcryptoL.pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt
        elif version == "Kyber768_90s":
            from pqcryptoL.pqcrypto.kem.kyber768_90s import generate_keypair, encrypt, decrypt
        elif version == "Kyber1024":
            from pqcryptoL.pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt
        else:
            from pqcryptoL.pqcrypto.kem.kyber1024_90s import generate_keypair, encrypt, decrypt
        
    def generate_keypair(self):
        public_key, secret_key = generate_keypair()
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----", "-----BEGIN SECRET KEY-----\n" + secret_key + "\n-----END SECRET KEY-----"
    
    def encrypt(self, public_key):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        public_key_start = "-----BEGIN PUBLIC KEY-----"
        public_key_end = "-----END PUBLIC KEY-----"

        # Získání klíče
        public_key = public_key.split(public_key_start)[1].split(public_key_end)[0].strip()

        public_key = base64.b64decode(public_key.encode('utf-8'))
        ciphertext, symmetrickey_original = encrypt(public_key)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        symmetrickey_original = base64.b64encode(symmetrickey_original).decode('utf-8')
        return "-----BEGIN CIPHER TEXT-----\n" + ciphertext + "\n-----END CIPHER TEXT-----", "-----BEGIN SYMMETRIC KEY-----\n" + symmetrickey_original + "\n-----END SYMMETRIC KEY-----"
    
    def decrypt(self,secret_key,ciphertext):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        secret_key_start = "-----BEGIN SECRET KEY-----"
        secret_key_end = "-----END SECRET KEY-----"

        # Získání klíče
        secret_key = secret_key.split(secret_key_start)[1].split(secret_key_end)[0].strip()

        # Oddělení záhlaví a závěrky a získání samotného klíče
        ciphertext_start = "-----BEGIN CIPHER TEXT-----"
        ciphertext_end = "-----END CIPHER TEXT-----"

        # Získání klíče
        ciphertext = ciphertext.split(ciphertext_start)[1].split(ciphertext_end)[0].strip()
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        symmetrickey_recovered = decrypt(secret_key, ciphertext)
        symmetrickey_recovered = base64.b64encode(symmetrickey_recovered).decode('utf-8')
        return "-----BEGIN SYMMETRIC KEY-----\n" + symmetrickey_recovered + "\n-----END SYMMETRIC KEY-----"
    
class KYBERPY:
    def __init__(self, version):
        global Kyber

        if version == "Kyber512":
            from kyberpy.kyber import Kyber512 as Kyber
        elif version == "Kyber768":
            from kyberpy.kyber import Kyber768 as Kyber
        else:
            from kyberpy.kyber import Kyber1024 as Kyber


    def generate_keypair(self):
        public_key, secret_key = Kyber.keygen() #generuje privatni s shared klice
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----", "-----BEGIN SECRET KEY-----\n" + secret_key + "\n-----END SECRET KEY-----"
    
    def encrypt(self, public_key):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        public_key_start = "-----BEGIN PUBLIC KEY-----"
        public_key_end = "-----END PUBLIC KEY-----"

        # Získání klíče
        public_key = public_key.split(public_key_start)[1].split(public_key_end)[0].strip()

        public_key = base64.b64decode(public_key.encode('utf-8'))
        ciphertext, symmetrickey_original = Kyber.enc(public_key)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        symmetrickey_original = base64.b64encode(symmetrickey_original).decode('utf-8') 
        #return ciphertext, symmetrickey_original
        return "-----BEGIN CIPHER TEXT-----\n" + ciphertext + "\n-----END CIPHER TEXT-----", "-----BEGIN SYMMETRIC KEY-----\n" + symmetrickey_original + "\n-----END SYMMETRIC KEY-----"
    
    def decrypt(self,secret_key,ciphertext):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        secret_key_start = "-----BEGIN SECRET KEY-----"
        secret_key_end = "-----END SECRET KEY-----"

        # Získání klíče
        secret_key = secret_key.split(secret_key_start)[1].split(secret_key_end)[0].strip()

        # Oddělení záhlaví a závěrky a získání samotného klíče
        ciphertext_start = "-----BEGIN CIPHER TEXT-----"
        ciphertext_end = "-----END CIPHER TEXT-----"

        # Získání klíče
        ciphertext = ciphertext.split(ciphertext_start)[1].split(ciphertext_end)[0].strip()

        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        symmetrickey_recovered = Kyber.dec(ciphertext,secret_key)
        symmetrickey_recovered = base64.b64encode(symmetrickey_recovered).decode('utf-8')
        #return symmetrickey_recovered
        return "-----BEGIN SYMMETRIC KEY-----\n" + symmetrickey_recovered + "\n-----END SYMMETRIC KEY-----"