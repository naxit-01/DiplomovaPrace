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
    
class Falcon1:
    """
    https://falcon-sign.info/

    https://github.com/tprest/falcon.py

    Stahnout repozitar. Nainstalovat numpy, pycryptodome

    hlavni program musi byt budu napsany v adresari falconu, nebo musi byt importovaci hlavicky upraveny na zaklade cesty

    Falcon je velmi pomaly a nejspis pro pouziti nevhodny, 
    """
    
    def test():
        from Falcon.falcon import SecretKey, PublicKey

        sk = SecretKey(512)
        pk = PublicKey(sk)

        sig = sk.sign(b"Hello")

        print(pk.verify(b"Hello", sig))

class SPHINCSPlus:
    
    """
    Z NIST jsem se podival na oficialni stranky SPHINCS+ https://sphincs.org/index.html

    Tam jsem nasel odkaz na jejich repozitar na github, kde maji jejich implementaci spihncs+ pro Python https://github.com/sphincs/pyspx

    staci naistalovat knihovnu pyspx nastrojem pip.

    Rodina SPHINCS+ ma nekolik algoritmu, ktere se lisi pouzitou hashovaci funkci. haraka_128f haraka_192f haraka_256f sha2_128f sha2_192f sha2_256f shake_128f shake_192f shake_256f haraka_128s haraka_192s haraka_256s sha2_128s sha2_192s sha2_256s shake_128s shake_192s shake_256s

    Haraka_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají hashovací funkci Haraka s různými délkami výstupu (128, 192 nebo 256 bitů). Haraka je konstrukce kryptografické hashovací funkce, která byla navržena pro rychlost a bezpečnost.

    SHA2_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají standardní hashovací funkce SHA-2 (Secure Hash Algorithm 2) s různými délkami výstupu (128, 192 nebo 256 bitů).

    SHAKE_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají SHA-3 variantu SHAKE (Secure Hash Algorithm KECCAK) s různými délkami výstupu (128, 192 nebo 256 bitů). SHAKE umožňuje generovat libovolně dlouhé hashovací hodnoty.

    Haraka_xxxs, SHA2_xxxs, SHAKE_xxxs (xxx je 128, 192 nebo 256): Tyto verze jsou stejné jako jejich odpovídající "f" varianty, ale s optimalizacemi pro snížení velikosti veřejných klíčů a podpisů. To znamená, že generované klíče a podpisy jsou kratší, což může být výhodné v prostředích s omezenými zdroji.
    """

    def __init__(self):
        
        from pathlib import Path
        import configparser

        # Cesta k aktuálnímu adresáři (tam, kde se spouští skript)
        current_directory = Path.cwd()

        # Cesta k souboru ve stejném adresáři jako skript
        file_path = f"{current_directory}\\config.ini"

        # Vypsání cesty
        print(file_path)
        config = configparser.ConfigParser()
        config.read("config.ini")

        algorithm = {}
        print("\nVERSION:")
        for key in config["VERSION"]:
            algorithm[key] = config['VERSION'][key]
            print(f"{key} = {config['VERSION'][key]}")

        
        import importlib


        # Importovat modul na základě názvu v proměnné
        global algorithm_module
        algorithm_module = importlib.import_module(algorithm["sphincsver"])

    
    def generate_keypair(self):
        # Alice generates a (public, secret) key pair
        import os
        seed = os.urandom(48)
        public_key, secret_key = algorithm_module.generate_keypair(seed)
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

        signature = algorithm_module.sign(message.encode('utf-8'), secret_key)
        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = algorithm_module.sign(message.encode('utf-8'), secret_key)
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
        assert algorithm_module.verify(message.encode('utf-8'), signature, public_key)
        return True




