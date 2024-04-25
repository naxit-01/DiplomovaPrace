# Napodobuji funkcionalitu bezne knihovny PyJWT 
# https://pyjwt.readthedocs.io/en/stable/index.html
import base64
import json
#from utility import get_time
import modules.signAlgLib as signAlgLib

def encode(payload, key, alg):
    # Získání třídy podle názvu algoritmu
    sign_alg = getattr(signAlgLib, alg, None)()

    # Hlavička
    header = {
        "alg": alg,  # Algoritmus pro podepisování
        "typ": "JWT"      # Typ tokenu
    }

    # Náplň
    payload = payload
    

    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

    signature = sign_alg.sign(key, f"{encoded_header}.{encoded_payload}")
    encoded_signature = base64.urlsafe_b64encode(json.dumps(signature).encode()).decode()

    jwt = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
    return jwt

def decode(jwt, public_key, alg=None): # Zmena oproti predloze. Pr
    try:
        # Rozdělení JWT podle teček
        parts = jwt.split(".")

        # Získání jednotlivých částí
        encoded_header = parts[0]
        encoded_payload = parts[1]
        encoded_signature = parts[2]
    except:
        return "wrong format"
    
    try:
        header = json.loads(base64.b64decode(encoded_header).decode('utf-8'))
        payload = json.loads(base64.b64decode(encoded_payload).decode('utf-8'))
        signature = json.loads(base64.b64decode(encoded_signature).decode('utf-8'))
    except:
        return "wrong encoding"

    if alg is None:
        alg = header["alg"]

    try:
        sign_alg = getattr(signAlgLib, alg, None)()
    except:
        return "wrong algorithm"
    
    if sign_alg.verify(public_key, f"{encoded_header}.{encoded_payload}",signature):
        return payload
    else:
        return "wrong public key"
