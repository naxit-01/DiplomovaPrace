import configparser
import base64
from secrets import compare_digest
import json
import datetime
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

from modules import get_time, load_config, create_jwt, read_jwt, check_jwt

NODE, ALGORITHM, CA = load_config('config.ini')

from modules.KEMalgorithm import *
from modules.signatures import *

kem_algorithm = globals()[ALGORITHM["kemalgorithm"]]()
sign_algorithm = globals()[ALGORITHM["signalgorithm"]]()

from modules.symmetric import symmetric_encryption,symmetric_decryption
cert_table = []

CA_sign_public_key, CA_sign_secret_key = sign_algorithm.generate_keypair()

# Otevření souboru v režimu zápisu
with open("CA_public_key.pem", "w") as file:
    # Zápis textu do souboru
    file.write(CA_sign_public_key)

def create_cert(subject, public_key, sign_alg):
    cert={
    "Version": "own_certificate",
    "Serial Number": len(cert_table),
    "Signature Algorithm": "označení algoritmu (ID)",
    "Issuer": "vydavatel",
    "Validity": "platnost",
    "Not Before": "nepoužívat před datem",
    "Not After": "nepoužívat po datu",
    "Subject": subject,
    "Subject Public Key Info": "informace o veřejném klíči vlastníka",
    "Public Key Algorithm": sign_alg,
    "public_key": public_key,
    "Signature Algorithm": "algoritmus pro certifikát (elektronický podpis)",
    "certifikát": "cert"
    }
    return cert

""""def create_jwt(alg, subject, payload):

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
    signature = sign_algorithm.sign(CA_sign_secret_key, f"{encoded_header}.{encoded_payload}")
    jwt = f"{encoded_header}.{encoded_payload}.{signature}"

    
    return header,payload,jwt"""

def register(subject):
    #values = json.loads(self.request.body.decode('utf-8'))
        
    sign_public_key, sign_secret_key = sign_algorithm.generate_keypair()
    print(sign_secret_key)
    cert = create_cert(subject,sign_public_key, sign_alg=ALGORITHM["signalgorithm"])


    cert_table.append(cert)
    print(cert)
    header,payload,response_jwt = create_jwt(ALGORITHM["signalgorithm"],
                                             f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
                                             {"private_key":sign_secret_key}, 
                                             sign_algorithm, 
                                             CA_sign_secret_key)
    return response_jwt

def find_public_key(hostname):
    for cert in cert_table:
        if cert["Subject"] == hostname:
            return cert["public_key"]
    print("Hostname nenalezen")
    return ""

class MainHandler(tornado.web.RequestHandler):
    symmetrical_key = ""
    async def post(self):
        request_type = self.request.headers.get('request_type')
        match request_type:
            case "KEM_public_key":
                data = json.loads(self.request.body.decode('utf-8'))
                # prijima verejny klic od klienta a vytvori z nej sdilene tajemstvi
                ciphertext, plaintext_original = kem_algorithm.encrypt(data["public_key"])

                #uklada si symetricky klic
                MainHandler.symmetrical_key=plaintext_original

                # odesila sdilene tajemstvi
                response = {
                    "ciphertext":ciphertext
                }
                self.write(json.dumps(response))
            case "encrypted_request":
                request = self.request.headers.get('request')
                response = ""
                encrypted_data = self.request.body
                if encrypted_data:
                    # Pokud jsou v těle požadavku nějaká data
                    # print("V těle požadavku jsou data.")
                    encrypted_data=json.loads(encrypted_data.decode())
                    # Najdu si verejny klic v databazi
                    subject = self.request.headers.get('hostname')
                    pk = find_public_key(subject)
                    jwt = symmetric_decryption(MainHandler.symmetrical_key, encrypted_data["encrypted_message"])
                    if check_jwt(jwt, pk, sign_algorithm) is True:
                        data = read_jwt(jwt)
                else:
                    # Pokud není v těle požadavku žádná data
                    # print("V těle požadavku nejsou žádná data.")
                    pass
                match request:
                    case "register":
                        subject = self.request.headers.get('hostname')
                        response_jwt = register(subject)
                        response = response_jwt

                    case "public_key":
                        # prijima zasifrovanou zpravu a pomoci symetrickeho klice ji desifruje
                        pk_hostname = data[1]["payload"]["hostname"]
                        pk = find_public_key(pk_hostname)
                        pk_hostname = {"public_key":pk}
                        header,payload,response_jwt = create_jwt(ALGORITHM["signalgorithm"], 
                                                                 f"{CA["ca_ip_address"]}:{CA["ca_port"]}", 
                                                                 pk_hostname, sign_algorithm,
                                                                 CA_sign_secret_key)
                        response = response_jwt
                        
                    case "other":
                        # prijima zasifrovanou zpravu a pomoci symetrickeho klice ji desifruje
                        decrypted_data = symmetric_decryption(MainHandler.symmetrical_key, data["encrypted_message"])
                        signed_data = json.loads(decrypted_data)

                        # overeni podpisu pomoci prijateho podpisoveho verejneho klice
                        if sign_algorithm.verify(signed_data["public_key"],signed_data["message"],signed_data["signature"]):
                            print(signed_data["message"])
                            self.write("thanks")
                        else:
                            self.write("invalid signature")

                # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
                encrypted_response = symmetric_encryption(MainHandler.symmetrical_key, response)
                self.write(json.dumps({"data":encrypted_response}))

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    #app.listen(ca_port)
    app.listen(CA["ca_port"], address=CA["ca_ip_address"])  # Změňte na vaši požadovanou IP adresu
    print(f"CA is running on http://{CA["ca_ip_address"]}:{CA["ca_port"]}")
    tornado.ioloop.IOLoop.current().start()
