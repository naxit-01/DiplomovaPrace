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

import base64
import json

"""def create_jwt(alg, subject, payload, sign_algorithm, sign_secret_key):

    # Hlavička
    header = {
        "alg": alg,  # Algoritmus pro podepisování
        "typ": "JWT"      # Typ tokenu
    }

    # Náplň
    payload = {
        "sub": subject,     # Identifikátor subjektu
        "name": "John Doe",      # Jméno uživatele
        "timestamp":get_time(),
        #"iat": datetime.datetime.utcnow().timestamp(),  # Čas vytvoření tokenu (UTC)
        #"exp": (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).timestamp(),  # Čas expirace tokenu (UTC)
        "payload":payload
    }

    # Zakódování do Base64 URL-safe
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    signature = sign_algorithm.sign(sign_secret_key, f"{encoded_header}.{encoded_payload}")
    jwt = f"{encoded_header}.{encoded_payload}.{signature}"

    
    return header,payload,jwt

def check_jwt(jwt, pk, sign_algorithm):
    # Rozdělení JWT podle teček
    parts = jwt.split(".")

    # Získání jednotlivých částí
    encoded_header = parts[0]
    encoded_payload = parts[1]
    signature = parts[2]

    return sign_algorithm.verify(pk, f"{encoded_header}.{encoded_payload}",signature)

def read_jwt(jwt):
    parts = jwt.split(".")

    # Získání jednotlivých částí
    encoded_header = parts[0]
    encoded_payload = parts[1]
    header = json.loads(base64.b64decode(encoded_header).decode('utf-8'))
    payload = json.loads(base64.b64decode(encoded_payload).decode('utf-8'))
    return header, payload"""

from modules.symmetric import symmetric_encryption,symmetric_decryption
from modules import jwt

def get_sign_private_key(my_address, CA, kem_algorithm):
    # Tato funkce vrati privatni klic, ktere nam poskytla CA

    # Komunikace s CA bude sifrovana, proto si nejprve dohodnu symetricky klic
    symmetrical_key = define_symmetric_key(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/", kem_algorithm, my_address)

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
    """if check_jwt(jwt_private_key,ca_pk, sign_algorithm) is True:        
        # Rozeberu jwt a vratim privatni klic, ktery mi poslala CA
        header_jwt, payload_jwt = read_jwt(jwt_private_key)
        private_key = payload_jwt["payload"]["private_key"]
        return private_key


    else: return "Invalid JWT"""

import requests

def define_symmetric_key(url, kem_algorithm, my_address):
    # Definuji si symetricky klic se kterym budu sifrovat a desifrovat data s protejskem viz url
    
    # Generuji vlastni dvojici klicu
    public_key, secret_key = kem_algorithm.generate_keypair()

    # Odesilam svuj public key na server a ziskavam cipher_text
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "KEM_public_key"}
    data = {'public_key': public_key}
    response = json.loads(requests.post(url, data=json.dumps(data), headers = headers).text)
    ciphertext=response["ciphertext"]

    # Pomoci cipher textu a sveho privatniho klice ziskavam symetricky klic
    plaintext_recovered = kem_algorithm.decrypt(secret_key, ciphertext)
    symmetrical_key = plaintext_recovered
    return symmetrical_key

def ask_public_key(hostname,sign_private_key, my_address, kem_algorithm, CA, ALGORITHM):
    symmetrical_key = define_symmetric_key(f'http://{CA["ca_ip_address"]}:{CA["ca_port"]}', kem_algorithm, my_address)

    # Hlavicka ktera rika kdo jsem a co chci udelat. Chci provest registraci
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':"public_key"}
    payload = {
        "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
        "hostname" : hostname
        }

    """header,payload,response_jwt = create_jwt(ALGORITHM["signalgorithm"],
                                             f"{my_address["ip_address"]}:{my_address["port"]}",
                                             data, 
                                             sign_algorithm, 
                                             sign_private_key)"""
    
    response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])

    #sifrovani zpravy pomoci symetrickeho klice a posila ji na server
    encrypted_message = symmetric_encryption(symmetrical_key, response_jwt)
    data = {'encrypted_message': encrypted_message}
    response = requests.post(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/",headers=headers, data=json.dumps(data)).text

    encrypted_data = (json.loads(response))["data"]
    payload_jwt = symmetric_decryption(symmetrical_key, encrypted_data)

    # Nactu si verejny klic z databaze (jediny CA verejny klic mam ulozeny)
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()

    """if check_jwt(payload_jwt, ca_pk, sign_algorithm):
        header, payload_jwt = read_jwt(payload_jwt)"""
    payload_jwt = jwt.decode(payload_jwt, ca_pk)
    return payload_jwt["public_key"]