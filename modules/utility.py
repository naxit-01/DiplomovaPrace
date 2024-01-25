import time

def get_time():

    # Získání aktuálního času v nanosekundách
    time_ns = time.time_ns()

    # Převod na čitelný text
    time_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_ns // 1000000000))

    # Přidání nanosekund do textu
    time_text += f".{time_ns % 1000000000:09d}"

    # Odstranění všech nečíselných znaků z řetězce
    time_digits = "".join(filter(str.isdigit, time_text))

    # Převod na float
    time_float = float(f"{time_digits[:-9]}.{time_digits[-9:]}")

    return time_float

import configparser

def load_config(file):
    from pathlib import Path

    # Cesta k aktuálnímu adresáři (tam, kde se spouští skript)
    current_directory = Path.cwd()

    # Cesta k souboru ve stejném adresáři jako skript
    file_path = f"{current_directory}\\config.ini"

    # Vypsání cesty
    print(file_path)
    config = configparser.ConfigParser()
    config.read(file)

    print("\nROLE:")
    for key in config["ROLE"]:
        globals()[key] = config['ROLE'][key]
        print(f"{key} = {config['ROLE'][key]}")

    algorithm = {}
    print("\nalgorithm:")
    for key in config["algorithm"]:
        algorithm[key] = config['algorithm'][key]
        #globals()[key] = config['algorithm'][key]
        print(f"{key} = {config['algorithm'][key]}")

    node = {}
    print("\nNODE:")
    for key in config["NODE"]:
        node[key] = config['NODE'][key]
        #globals()[key] = config['NODE'][key]
        print(f"{key} = {config['NODE'][key]}")

    ca = {}
    print("\nCA:")
    for key in config["CA"]:
        ca[key] = config['CA'][key]
        print(f"{key} = {config['CA'][key]}")

    return node, algorithm, ca


"""import json


from modules.symmetric import symmetric_encryption,symmetric_decryption
from modules import jwt

def get_sign_private_key(my_address, CA, ALGORITHM):
    # Tato funkce vrati privatni klic, ktere nam poskytla CA
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()
    # Komunikace s CA bude sifrovana, proto si nejprve dohodnu symetricky klic
    symmetrical_key = define_symmetric_key(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/", ALGORITHM["kemalgorithm"], my_address, ca_pk)

    # Hlavicka ktera rika kdo jsem a co chci udelat. Chci provest registraci
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':"register"}
    
    # Odesilam pozadavek a jak odpoved se mi vrati zasifrovany jwt token
    encrypted_data = requests.post(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/",headers=headers).text
    encrypted_data = json.loads(encrypted_data)

    # Desifruji token
    jwt_private_key = symmetric_decryption(symmetrical_key, encrypted_data["data"])

    # Nactu si verejny klic z databaze (jediny CA verejny klic mam ulozeny)
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()

    # Overim zda mi jwt poslala doopravdy moje CA a ziskam data
    payload_jwt = jwt.decode(jwt_private_key, ca_pk)
    return payload_jwt["private_key"]

import requests

import modules.KEMalgorithm as KEMalgorithm

def define_symmetric_key(url, kem_algorithm, my_address, pk):
    # Definuji si symetricky klic se kterym budu sifrovat a desifrovat data s protejskem viz url
    

    kem_alg = getattr(KEMalgorithm, kem_algorithm, None)()
    # Generuji vlastni dvojici klicu
    public_key, secret_key = kem_alg.generate_keypair()

    # Odesilam svuj public key na server a ziskavam cipher_text
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "KEM_public_key"}
    data = {'public_key': public_key}
    response_jwt = requests.post(url, headers = headers, data=json.dumps(data)).text
    
    payload_jwt = jwt.decode(response_jwt, pk)

    ciphertext=payload_jwt["ciphertext"]

    # Pomoci cipher textu a sveho privatniho klice ziskavam symetricky klic
    plaintext_recovered = kem_alg.decrypt(secret_key, ciphertext)
    symmetrical_key = plaintext_recovered
    return symmetrical_key

def ask_public_key(hostname,sign_private_key, my_address, CA, ALGORITHM):
    # Nactu si verejny klic z databaze (jediny CA verejny klic mam ulozeny)
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()

    symmetrical_key = define_symmetric_key(f'http://{CA["ca_ip_address"]}:{CA["ca_port"]}', ALGORITHM["kemalgorithm"], my_address, ca_pk)

    # Hlavicka ktera rika kdo jsem a co chci udelat. Chci provest registraci
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':"public_key"}
    payload = {
        "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
        "hostname" : hostname
        }
    
    response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])

    #sifrovani zpravy pomoci symetrickeho klice a posila ji na server
    encrypted_message = symmetric_encryption(symmetrical_key, response_jwt)
    data = {'encrypted_message': encrypted_message}
    response = requests.post(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/",headers=headers, data=json.dumps(data)).text

    encrypted_data = (json.loads(response))["data"]
    payload_jwt = symmetric_decryption(symmetrical_key, encrypted_data)

    payload_jwt = jwt.decode(payload_jwt, ca_pk)
    return payload_jwt["public_key"]"""