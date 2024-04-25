import base64

class DILITHIUM_PQCRYPTO:
    def __init__(self):
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        version = config.get("ALGORITHM", "signversion_DP")

        global generate_keypair, sign, verify

        #from pqcrypto.sign.dilithium4 import generate_keypair, sign, verify
        if version == "dilithium2":
            from pqcryptoL.pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
        elif version == "dilithium3":
            from pqcryptoL.pqcrypto.sign.dilithium3 import generate_keypair, sign, verify
        else:
            from pqcryptoL.pqcrypto.sign.dilithium4 import generate_keypair, sign, verify

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
    
class FALCON_PQCRYPTO:
    def __init__(self):
        global generate_keypair, sign, verify
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        version = config.get("ALGORITHM", "signversion_FP")

        if version == "falcon512":
            from pqcryptoL.pqcrypto.sign.falcon_512 import generate_keypair, sign, verify
        if version == "falcon1024":
            from pqcryptoL.pqcrypto.sign.falcon_1024 import generate_keypair, sign, verify
        

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
    
class FALCON_official:
    """
    https://falcon-sign.info/

    https://github.com/tprest/falcon.py

    Stahnout repozitar. Nainstalovat numpy, pycryptodome

    hlavni program musi byt budu napsany v adresari falconu, nebo musi byt importovaci hlavicky upraveny na zaklade cesty

    Falcon je velmi pomaly a nejspis pro pouziti nevhodny, 
    """
    
    def __init__(self):
        global version, pickle
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        version = config.get("ALGORITHM", "signversion_FO")
        from Falcon_official.falcon import SecretKey, PublicKey
        import pickle
        if version == "512":
            version = 512
        else:
            version = 1024

    def test(self):
        from Falcon_official.falcon import SecretKey, PublicKey

        sk = SecretKey(512)
        pk = PublicKey(sk)

        sig = sk.sign(b"Hello")

        print(pk.verify(b"Hello", sig))

    def generate_keypair(self):
        from Falcon_official.falcon import SecretKey, PublicKey
        # Alice generates a (public, secret) key pair
        version2 = version
        sk = SecretKey(version2)
        pk = PublicKey(sk)
        public_key = pickle.dumps(pk)
        secret_key = pickle.dumps(sk)
        public_key = base64.b64encode(public_key).decode('utf-8')
        secret_key = base64.b64encode(secret_key).decode('utf-8')
        return "-----BEGIN PUBLIC KEY-----\n" + public_key + "\n-----END PUBLIC KEY-----", "-----BEGIN SECRET KEY-----\n" + secret_key + "\n-----END SECRET KEY-----"

    def sign(self, secret_key, message):
        # Oddělení záhlaví a závěrky a získání samotného klíče
        secret_key_start = "-----BEGIN SECRET KEY-----"
        secret_key_end = "-----END SECRET KEY-----"

        # Získání klíče
        secret_key = secret_key.split(secret_key_start)[1].split(secret_key_end)[0].strip()
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        sk = pickle.loads(secret_key)
        # Alice signs her message using her secret key

        #message = base64.b64decode(message.encode('utf-8'))
        signature = sk.sign(message.encode('utf-8'))
        signature = base64.b64encode(signature).decode('utf-8')
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
        sig = base64.b64decode(signature.encode('utf-8'))
        pk = pickle.loads(public_key)
        assert pk.verify(message.encode('utf-8'), sig)
        return True

class SPHINCSPlus_PQCRYPTO:
    def __init__(self):
        global generate_keypair, sign, verify
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        version = config.get("ALGORITHM", "signversion_SP")

        if version == "sphincs_haraka_128f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_128f_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_128f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_128f_simple import generate_keypair, sign, verify
        elif version == "sphincs_haraka_128s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_128s_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_128s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_128s_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_192f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_192f_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_192f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_192f_simple import generate_keypair, sign, verify
        elif version == "sphincs_haraka_192s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_192s_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_192s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_192s_simple import generate_keypair, sign, verify
        elif version == "sphincs_haraka_256f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_256f_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_256f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_256f_simple import generate_keypair, sign, verify
        elif version == "sphincs_haraka_256s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_256s_robust import generate_keypair, sign, verify
        elif version == "sphincs_haraka_256s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_haraka_256s_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_128f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_128f_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_128f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_128f_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_128s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_128s_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_128s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_128s_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_192f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_192f_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_192f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_192f_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_192s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_192s_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_192s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_192s_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_256f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_256f_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_256f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_256f_simple import generate_keypair, sign, verify
        elif version == "sphincs_sha256_256s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_256s_robust import generate_keypair, sign, verify
        elif version == "sphincs_sha256_256s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_sha256_256s_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_128f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_128f_robust import generate_keypair, sign, verify
        elif version == "sphincs_shake256_128f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_128f_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_128s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_128s_robust import generate_keypair, sign, verify
        elif version == "sphincs_shake256_128s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_128s_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_192f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_192f_robust import generate_keypair, sign, verify
        elif version == "sphincs_shake256_192f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_192f_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_192s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_192s_robust import generate_keypair, sign, verify
        elif version == "sphincs_shake256_192s_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_192s_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_256f_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_256f_robust import generate_keypair, sign, verify
        elif version == "sphincs_shake256_256f_simple":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_256f_simple import generate_keypair, sign, verify
        elif version == "sphincs_shake256_256s_robust":
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_256s_robust import generate_keypair, sign, verify
        else:
            from pqcryptoL.pqcrypto.sign.sphincs_shake256_256s_simple import generate_keypair, sign, verify
            
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
    
class SPHINCSPlus_official:
    
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
        
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        algorithm = config.get("ALGORITHM", "signversion_SO")

        import importlib

        # Importovat modul na základě názvu v proměnné
        global algorithm_module
        algorithm_module = importlib.import_module(algorithm)

        


    
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

        #signature = algorithm_module.sign(message.encode('utf-8'), secret_key)
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

class SPHINCSPlus_Tottifi:
    
    """
    https://github.com/tottifi/sphincs-python

    Rodina SPHINCS+ ma nekolik algoritmu, ktere se lisi pouzitou hashovaci funkci. haraka_128f haraka_192f haraka_256f sha2_128f sha2_192f sha2_256f shake_128f shake_192f shake_256f haraka_128s haraka_192s haraka_256s sha2_128s sha2_192s sha2_256s shake_128s shake_192s shake_256s

    Haraka_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají hashovací funkci Haraka s různými délkami výstupu (128, 192 nebo 256 bitů). Haraka je konstrukce kryptografické hashovací funkce, která byla navržena pro rychlost a bezpečnost.

    SHA2_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají standardní hashovací funkce SHA-2 (Secure Hash Algorithm 2) s různými délkami výstupu (128, 192 nebo 256 bitů).

    SHAKE_xxxf (xxx je 128, 192 nebo 256): Tyto verze používají SHA-3 variantu SHAKE (Secure Hash Algorithm KECCAK) s různými délkami výstupu (128, 192 nebo 256 bitů). SHAKE umožňuje generovat libovolně dlouhé hashovací hodnoty.

    Haraka_xxxs, SHA2_xxxs, SHAKE_xxxs (xxx je 128, 192 nebo 256): Tyto verze jsou stejné jako jejich odpovídající "f" varianty, ale s optimalizacemi pro snížení velikosti veřejných klíčů a podpisů. To znamená, že generované klíče a podpisy jsou kratší, což může být výhodné v prostředích s omezenými zdroji.
    """

    def __init__(self):
        
        import configparser

        config = configparser.ConfigParser()
        config.read("config.ini")

        version = config.get("ALGORITHM", "signversion_ST")
        casti = version.split('_')

        n = int(casti[0][1:]) 
        w = int(casti[1][1:])
        h = int(casti[2][1:])
        d = int(casti[3][1:])
        k = int(casti[4][1:])
        a = int(casti[5][1:])


        from sphincs_Tottifi.package.sphincs import Sphincs
        global sphincs
        sphincs = Sphincs()
        sphincs.set_n(n)
        sphincs.set_w(w)
        sphincs.set_h(h)
        sphincs.set_d(d)
        sphincs.set_k(k)
        sphincs.set_a(a)

    
    def generate_keypair(self):
        # Alice generates a (public, secret) key pair
        import os
        seed = os.urandom(48)
        secret_key, public_key = sphincs.generate_key_pair()
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

        #signature = algorithm_module.sign(message.encode('utf-8'), secret_key)
        # Alice signs her message using her secret key
        secret_key = base64.b64decode(secret_key.encode('utf-8'))
        #message = base64.b64decode(message.encode('utf-8'))
        signature = sphincs.sign(message.encode('utf-8'), secret_key)
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
        assert sphincs.verify(message.encode('utf-8'), signature, public_key)
        return True




