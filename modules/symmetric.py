from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64


def symmetric_encryption(key, plaintext):
    
    #symetricke sifrovani
    key = base64.b64decode(key.encode('utf-8'))
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return [base64.b64encode(cipher.iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')]

def symmetric_decryption(key, dataset):
    key = base64.b64decode(key.encode('utf-8'))
    iv, cryptedtext = dataset
    iv = base64.b64decode(iv.encode('utf-8'))
    cryptedtext = base64.b64decode(cryptedtext.encode('utf-8'))

    #symetricke desifrovani na zaklade symetrickeho klice a inicializacniho vektoru
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(cryptedtext), AES.block_size)
    return plaintext.decode()