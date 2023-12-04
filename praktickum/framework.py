
class PQCRYPTO:
    def __init__(self):
        global generate_keypair, encrypt, decrypt
        from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

    def generate_keypair(self):
        public_key, secret_key = generate_keypair()
        return public_key, secret_key
    
    def encrypt(self, public_key):
        ciphertext, symmetrickey_original = encrypt(public_key)
        return ciphertext, symmetrickey_original
    
    def decrypt(self,secret_key,ciphertext):
        symmetrickey_recovered = decrypt(secret_key, ciphertext)
        return symmetrickey_recovered

class KYBERPY:
    def __init__(self):
        global Kyber512
        from kyberpy.kyber import Kyber512

    def generate_keypair(self):
        pk, sk = Kyber512.keygen() #generuje privatni s shared klice
        return pk, sk
    
    def encrypt(self, public_key):
        ciphertext, symmetrickey_original = Kyber512.enc(public_key) 
        return ciphertext, symmetrickey_original
    
    def decrypt(self,secret_key,ciphertext):
        symmetrickey_recovered = Kyber512.dec(ciphertext,secret_key)
        return symmetrickey_recovered

#cipheralgorithm = PQCRYPTO()
cipheralgorithm = KYBERPY()

# Alice generates a (public, secret) key pair
public_key, secret_key = cipheralgorithm.generate_keypair()


# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = cipheralgorithm.encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = cipheralgorithm.decrypt(secret_key, ciphertext)

from secrets import compare_digest
if compare_digest(plaintext_original, plaintext_recovered):
    symetrical_key = plaintext_original

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def sifrovani(klic, plaintext):
    cipher = AES.new(klic, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return [cipher.iv, ciphertext]

def desifrovani(klic, ciphertext):
    iv, ciphertext = ciphertext
    cipher = AES.new(klic, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


plaintext = "Toto je můj vlastní text"

# Volání funkce pro šifrování
ciphertext = sifrovani(symetrical_key, plaintext)

# Volání funkce pro dešifrování
vysledek = desifrovani(symetrical_key, ciphertext)

print(vysledek)  # Toto by mělo vypsat "Toto je můj vlastní text"




print("end")

