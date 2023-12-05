import configparser
import base64
from secrets import compare_digest

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
    symetrical_key = plaintext_original
"""

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
def print_hello():
    servers_ciphertext = []
    clients_symmetrical_key = ""
    while True:
        # Každých 5 vteřin vypíše "hello"
        
        # Vytvoření socketu
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Nastavení IP adresy a portu serveru
        server_address = ('localhost', 9999)
        s.connect(server_address)

        try:
            #Diffie-Helman
            #Iam Alice
            # Alice generates a (public, secret) key pair
            public_key, secret_key = cipheralgorithm.generate_keypair()

            #odeslani klice (jeho kodovani, rozdeleni a po castech odeslani)
            public_key_coded = base64.b64encode(public_key).decode('utf-8')
            original_data = base64.b64decode(public_key_coded.encode('utf-8'))
            
            if compare_digest(public_key, original_data):
                print("KLIENT: klice jsou stejne")
            print(f'KLIENT: Odesílání: public_key')

            strings = [public_key_coded[i:i+1000] for i in range(0, len(public_key_coded), 1000)]
            c = str(len(strings)).zfill(3)
            strings = [strings[i] + str(i).zfill(3) + c for i in range(len(strings))]     

            for i in range(len(strings)):
                data = json.dumps({"public_key": strings[i]})
                s.sendall(data.encode('utf-8'))


            # Přijetí odpovědi od serveru (ziskavam ciphertext)
            data = s.recv(1024)
            #print(f'KLIENT: Přijatá: {ciphertext.decode("utf-8")}')

            data = data.decode("utf-8")
            data_received = json.loads(data)
            if 'ciphertext' in data_received:
                print(f"SERVER: dostali jsme cast ciphertext")
                servers_ciphertext.append(data_received["ciphertext"])
                number = int(data_received["ciphertext"][-3:])
                if number == len(servers_ciphertext):
                    print("KLIENT: jsme komplet")
                    servers_ciphertext.sort(key=lambda s: int(s[-6:-3]))
                    servers_ciphertext = [s[:-6] for s in servers_ciphertext]
                    servers_ciphertext = ''.join(servers_ciphertext)
                    servers_ciphertext = base64.b64decode(servers_ciphertext.encode('utf-8'))

                    plaintext_recovered = cipheralgorithm.decrypt(secret_key, servers_ciphertext)
                    clients_symmetrical_key = plaintext_recovered
            
            # Odeslání dat serveru
            message = 'Toto je zprava. Bude opakovana.'

            # Volání funkce pro šifrování
            encrypted_message = sifrovani(symetrical_key, message)

            encrypted_message = [base64.b64encode(x).decode('utf-8') for x in encrypted_message]
            encrypted_message = json.dumps(encrypted_message)
            print(f'KLIENT: Odesílání: sifrovane zpravy')
            s.sendall(encrypted_message.encode('utf-8'))

            # Přijetí odpovědi od serveru
            data = s.recv(1024)
            print(f'KLIENT: Přijatá: {data.decode("utf-8")}')

        except Exception as e:
            print(f"Dostali jsme jinou zprávu {e}")

        finally:
            # Uzavření spojení
            s.close()
        time.sleep(5)

# Spustí funkci print_hello v samostatném vlákně
threading.Thread(target=print_hello).start()

#Server cast
while True:
    # Čekání na spojení
    print('Čekání na připojení...')
    connection, client_address = s.accept()

    clients_public_key = []
    servers_symmetrical_key = ""
    try:
        print('SERVER: Spojení z', client_address)

        # Přijímání dat a odesílání odpovědi
        while True:
            data = connection.recv(1024)
            if data:                
                try:
                    data = data.decode("utf-8")
                    data_received = json.loads(data)
                    if 'public_key' in data_received:
                        print(f"SERVER: dostali jsme cast public_key")
                        clients_public_key.append(data_received["public_key"])
                        number = int(data_received["public_key"][-3:])
                        if number == len(clients_public_key):
                            print("SERVER: mame kompletni public_key klienta")
                            clients_public_key.sort(key=lambda s: int(s[-6:-3]))
                            clients_public_key = [s[:-6] for s in clients_public_key]
                            clients_public_key = ''.join(clients_public_key)
                            clients_public_key = base64.b64decode(clients_public_key.encode('utf-8'))
                            ciphertext, plaintext_original = cipheralgorithm.encrypt(clients_public_key)
                            server_symmetrical_key = plaintext_original
                            
                            #odeslani klice (jeho kodovani, rozdeleni a po castech odeslani)
                            ciphertext_coded = base64.b64encode(ciphertext).decode('utf-8')
                            original_data = base64.b64decode(ciphertext_coded.encode('utf-8'))
                            if compare_digest(ciphertext, original_data):
                                print("SERVER: klice jsou stejne, mame ciphertext")
                            print(f'SERVER: Odesílání: ciphertext')

                            strings = [ciphertext_coded[i:i+1000] for i in range(0, len(ciphertext_coded), 1000)]
                            c = str(len(strings)).zfill(3)
                            strings = [strings[i] + str(i).zfill(3) + c for i in range(len(strings))]     

                            for i in range(len(strings)):
                                data = json.dumps({"ciphertext": strings[i]})
                                connection.sendall(data.encode('utf-8'))                            
                    else:
                        print("SERVER: Dostali jsme jinou zprávu")
                        encryptedtext=data
                        # Volání funkce pro dešifrování
                        encryptedtext = json.loads(encryptedtext)
                        #ciphertext = [base64.b64decode(x).decode('utf-8') for x in ciphertext]
                        #ciphertext = [base64.b64decode(x.encode('utf-8')).decode('utf-8') for x in ciphertext]
                        """for x in encryptedtext:
                            x = base64.b64decode(x.encode('utf-8'))"""
                        encryptedtext = [base64.b64decode(x.encode('utf-8')) for x in encryptedtext]
                        decrypted_data = desifrovani(symetrical_key, encryptedtext)
                        print("SERVER: Dostali jsme sifrovanou zpravu")
                        print(f"SERVER: {decrypted_data}")
                except json.JSONDecodeError as e:
                    print(f"Dostali jsme jinou zprávu {e}")
                
                #print('SERVER: Přijatá data: {!r}'.format(data))
                #print('SERVER: Odesílání dat zpět klientovi')

                #connection.sendall(data)
            else:
                print('SERVER: Žádná data od', client_address)
                break

    finally:
        # Uzavření spojení
        connection.close()


print("end")

