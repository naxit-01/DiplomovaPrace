import configparser
import base64
from secrets import compare_digest

global ksk
ksk="nic"
global ssk
ssk="nic"

def load_config(file):
    config = configparser.ConfigParser()
    config.read(file)

    print("\nROLE:")
    for key in config["ROLE"]:
        globals()[key] = config['ROLE'][key]
        print(f"{key} = {config['ROLE'][key]}")

    print("\nalgorithm:")
    for key in config["algorithm"]:
        globals()[key] = config['algorithm'][key]
        print(f"{key} = {config['algorithm'][key]}")

load_config('config.ini')

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

cipheralgorithm = globals()[cipheralgorithm]()

"""# Alice generates a (public, secret) key pair
public_key, secret_key = cipheralgorithm.generate_keypair()


# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = cipheralgorithm.encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = cipheralgorithm.decrypt(secret_key, ciphertext)


if compare_digest(plaintext_original, plaintext_recovered):
    symetrical_key = plaintext_original"""


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def symmetric_encryption(key, plaintext):
    
    #symetricke sifrovani
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return [cipher.iv, ciphertext]

def symmetric_decryption(key, dataset):
    
    #symetricke desifrovani na zaklade symetrickeho klice a inicializacniho vektoru
    iv, cryptedtext = dataset
    """print(f"desifrovani")
    print(f"klic {key}")
    print(f"iv: {iv}")
    print(f"ciphertext: {cryptedtext}")"""
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(cryptedtext), AES.block_size)
    return plaintext.decode()


"""

import time

# Otevření souboru v režimu pro čtení a zápis
with open('system_logs.txt', 'r+') as f:
    while True:  # Neustálý cyklus
        plaintext = f.read()  # Načtení dat ze souboru
        f.seek(0)  # Nastavení ukazatele na začátek souboru
        f.truncate()  # Smazání obsahu souboru

        # Volání funkce pro šifrování
        ciphertext = sifrovani(symetrical_key, plaintext)

        # Volání funkce pro dešifrování
        vysledek = desifrovani(symetrical_key, ciphertext)

        print(vysledek)  # Toto by mělo vypsat "Toto je můj vlastní text"        
        with open("downloaded", "a") as downloaded:
            downloaded.write(vysledek)
        time.sleep(5)  # Pauza na 5 sekund"""


import socket
import time
import threading
import json
# Vytvoření socketu
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Nastavení IP adresy a portu
server_address = ('localhost', 9999)
s.bind(server_address)

# Naslouchání příchozím spojením
s.listen(1)

#Client cast
def start_client():
    buffer = []
    servers_ciphertext = ""
    clients_symmetrical_key = ""
    while True:
        # Každých 5 vteřin vypíše "posle data na server"
        
        # Vytvoření socketu
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Nastavení IP adresy a portu serveru
        server_address = ('localhost', 9999)
        s.connect(server_address)

        try:
            # Diffie-Helman
            # Iam Alice
            # Alice generates a (public, secret) key pair
            clients_public_key, secret_key = cipheralgorithm.generate_keypair()

            # Odeslani klice (jeho kodovani, rozdeleni a po castech odeslani)
            print(f'KLIENT: Odesílání: public_key')
            public_key_coded = base64.b64encode(clients_public_key).decode('utf-8')
            #clients_original_data = base64.b64decode(public_key_coded.encode('utf-8'))
            strings = [public_key_coded[i:i+1000] for i in range(0, len(public_key_coded), 1000)]
            c = str(len(strings)).zfill(3)
            strings = [strings[i] + str(i).zfill(3) + c for i in range(len(strings))]     

            for i in range(len(strings)):
                data = json.dumps({"public_key": strings[i]})
                s.sendall(data.encode('utf-8'))


            # Přijetí odpovědi od serveru (ziskavam sdilene tajemstvi)
            data_received = s.recv(1024)
            data_received = json.loads(data_received.decode("utf-8"))

            if 'ciphertext' in data_received:
                print(f"KLIENT: dostali jsme cast ciphertext")
                buffer.append(data_received["ciphertext"])
                if int(data_received["ciphertext"][-3:]) == len(buffer):
                    # Pokud jsme ubdrzeli vsechny data pro sestaveni sdileneho tajemstvi, vytvorime symetricky klic
                    
                    # Sestaveni sdileneho tajemstvi
                    print("KLIENT: jsme komplet")
                    buffer.sort(key=lambda s: int(s[-6:-3]))
                    buffer = [s[:-6] for s in buffer]
                    servers_ciphertext = ''.join(buffer)
                    buffer = []
                    servers_ciphertext = base64.b64decode(servers_ciphertext.encode('utf-8'))
                    
                    # Vytvoreni symetrickeho klice z prenesenoho tajemstvi
                    plaintext_recovered = cipheralgorithm.decrypt(secret_key, servers_ciphertext)
                    clients_symmetrical_key = plaintext_recovered
                    print("KLIENT: mam symetricky klic")

            
            # Odeslání dat serveru
            message = 'Toto je zprava. Bude opakovana.'

            # Volání funkce pro šifrování
            encrypted_message = symmetric_encryption(clients_symmetrical_key, message)
            #decrypted_data = desifrovani(clients_symmetrical_key, encrypted_message)

            # Zakodovani a odesleni sifrovane zpravy
            encrypted_message = [base64.b64encode(x).decode('utf-8') for x in encrypted_message]
            encrypted_message = json.dumps(encrypted_message)
            print(f'KLIENT: Odesílání: sifrovane zpravy')
            s.sendall(encrypted_message.encode('utf-8'))

            # Přijetí odpovědi od serveru
            #data = s.recv(1024)
            #print(f'KLIENT: Přijatá: {data.decode("utf-8")}')

        except Exception as e:
            print(f"KLIENT: Dostali jsme chybovou zprávu {e}")

        finally:
            # Uzavření spojení
            s.close()
        time.sleep(5)

# Spustí funkci klienta v samostatném vlákně
threading.Thread(target=start_client).start()

#Server cast
while True:
    # Čekání na spojení
    print('Čekání na připojení...')
    connection, client_address = s.accept()

    buffer = []
    clients_public_key = ""
    servers_symmetrical_key = ""
    try:
        print('SERVER: Spojení z', client_address)

        # Přijímání dat a odesílání odpovědi
        while True:
            data = connection.recv(1024)
            if data:                
                try:
                    data_received = data.decode("utf-8")
                    data_received = json.loads(data_received)
                    if 'public_key' in data_received:

                        # Pokud jsme prijali cast public key ulozime ho do listu a pockame na zbytek
                        print(f"SERVER: dostali jsme cast public_key")
                        buffer.append(data_received["public_key"])

                        if int(data_received["public_key"][-3:]) == len(buffer):

                            # Pokud mame vsechny casti public key muzeme ho zkompilovat
                            print("SERVER: mame kompletni public_key klienta")
                            buffer.sort(key=lambda s: int(s[-6:-3]))
                            buffer = [s[:-6] for s in buffer]
                            clients_public_key = ''.join(buffer)
                            buffer = []
                            clients_public_key = base64.b64decode(clients_public_key.encode('utf-8'))

                            # Vytvoreni sdileneho tajemstvi
                            ciphertext, plaintext_original = cipheralgorithm.encrypt(clients_public_key)
                            servers_symmetrical_key = plaintext_original
                            print("SERVER: mam symetricky klic")
                            
                            # Odeslani klice (jeho kodovani, rozdeleni a po castech odeslani)
                            ciphertext_coded = base64.b64encode(ciphertext).decode('utf-8')
                            original_data = base64.b64decode(ciphertext_coded.encode('utf-8'))

                            strings = [ciphertext_coded[i:i+1000] for i in range(0, len(ciphertext_coded), 1000)]
                            c = str(len(strings)).zfill(3)
                            strings = [strings[i] + str(i).zfill(3) + c for i in range(len(strings))]     

                            print("SERVER: Odesilame ciphertext")
                            for i in range(len(strings)):
                                data = json.dumps({"ciphertext": strings[i]})
                                connection.sendall(data.encode('utf-8'))                            
                    else:
                        print("SERVER: Dostali jsme zprávu")
                        data_received=data

                        # Dekodovani zpravy
                        data_received = json.loads(data_received)                        
                        list = [base64.b64decode(x.encode('utf-8')) for x in data_received]

                        # Desifrovani zpravy
                        decrypted_data = symmetric_decryption(servers_symmetrical_key, list)
                        print("SERVER: Dostali jsme sifrovanou zpravu")
                        print(f"SERVER: {decrypted_data}")
                except Exception as e:
                    print(f"Dostali jsme chybovou zprávu {e}")
                
                #print('SERVER: Přijatá data: {!r}'.format(data))
                #print('SERVER: Odesílání dat zpět klientovi')

                #connection.sendall("Diky!".encode("UTF-8"))
            else:
                print('SERVER: Žádná data od', client_address)
                break

    finally:
        # Uzavření spojení
        connection.close()


print("end")

