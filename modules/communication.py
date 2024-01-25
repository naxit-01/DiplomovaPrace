from modules import jwt
import json
from modules.symmetric import symmetric_decryption, symmetric_encryption
import requests

def send_request(ip_address, port, payload, sign_private_key, my_address, CA, ALGORITHM, request=""):
    # podepsani a zasifrovani zpravy a jeji odeslani, nasledne prijeti odpovedi, jeji desifrovani a kontrola podpisu
    pk = ask_public_key(f"{ip_address}:{port}",sign_private_key, my_address, CA, ALGORITHM)
    symmetric_key = define_symmetric_key(f"http://{ip_address}:{port}/", ALGORITHM, my_address, pk, sign_sk = sign_private_key)
    
    message_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
    encrypted_message = symmetric_encryption(symmetric_key, message_jwt)
    
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':request}
    data = {'encrypted_message': encrypted_message}
    encrypted_response = json.loads(requests.post(f"http://{ip_address}:{port}/", headers = headers, data=json.dumps(data)).text)
    
    response_jwt = symmetric_decryption(symmetric_key, encrypted_response["encrypted_message"])
    response = jwt.decode(response_jwt,pk)
    return response

def get_sign_private_key(my_address, CA, ALGORITHM):
    # Tato funkce vrati privatni klic, ktere nam poskytla CA
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()
    # Komunikace s CA bude sifrovana, proto si nejprve dohodnu symetricky klic
    # Tuto jedinou dohodu provedu bez sveho privatniho klice a to proto, ze jeste zadny nemam a prave si o nej zadam. Az ho mit budu tak budu podepisovat i zadosti o KEM algoritmus
    symmetrical_key = define_symmetric_key(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/", ALGORITHM, my_address, ca_pk)

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


import modules.KEMalgorithm as KEMalgorithm

def define_symmetric_key(url, ALGORITHM, my_address, pk, sign_sk = None):
    # Definuji si symetricky klic se kterym budu sifrovat a desifrovat data s protejskem viz url
    
    kem_alg = getattr(KEMalgorithm, ALGORITHM["kemalgorithm"], None)()
    # Generuji vlastni dvojici klicu
    public_key, secret_key = kem_alg.generate_keypair()

    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "KEM_public_key"}    
    payload = {
        "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
        "public_key": public_key
    }

    # Pokud mam sign_private_key tak odesilana data podepisu, jinak poslu bez podpisu
    # Pouze kdyz zadam a privatni podepisovaci klic tak data nemohu podepsat, jinak ano
    if sign_sk is None:
        data = payload
        headers["mode"] = "emergency"
    else:
        data = jwt.encode(payload, sign_sk, ALGORITHM["signalgorithm"])
        headers["mode"] = "ordinary"

    # Odesilam svuj public key na server a ziskavam cipher_text
    response_jwt = requests.post(url, headers = headers, data=json.dumps(data)).text
    payload_jwt = jwt.decode(response_jwt, pk)

    ciphertext=payload_jwt["ciphertext"]

    # Pomoci cipher textu a sveho privatniho klice ziskavam symetricky klic
    plaintext_recovered = kem_alg.decrypt(secret_key, ciphertext)
    symmetrical_key = plaintext_recovered
    return symmetrical_key

def ask_public_key(subject, sign_private_key, my_address, CA, ALGORITHM):
    # Nactu si verejny klic z databaze (jediny CA verejny klic mam ulozeny)
    with open("CA_public_key.pem", "r") as file:
        ca_pk = file.read()

    symmetrical_key = define_symmetric_key(f'http://{CA["ca_ip_address"]}:{CA["ca_port"]}', ALGORITHM, my_address, ca_pk, sign_sk = sign_private_key)

    # Hlavicka ktera rika kdo jsem a co chci udelat. Chci provest registraci
    headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':"public_key"}
    payload = {
        "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
        "hostname" : subject
        }
    
    response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])

    #sifrovani zpravy pomoci symetrickeho klice a posila ji na server
    encrypted_message = symmetric_encryption(symmetrical_key, response_jwt)
    data = {'encrypted_message': encrypted_message}
    response = requests.post(f"http://{CA["ca_ip_address"]}:{CA["ca_port"]}/",headers=headers, data=json.dumps(data)).text

    encrypted_data = (json.loads(response))["data"]
    payload_jwt = symmetric_decryption(symmetrical_key, encrypted_data)

    payload_jwt = jwt.decode(payload_jwt, ca_pk)
    return payload_jwt["public_key"]