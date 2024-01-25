import configparser
import base64
from secrets import compare_digest
import json
import datetime
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

from modules import get_time, load_config
from modules import jwt

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


def register(subject):
    #values = json.loads(self.request.body.decode('utf-8'))
        
    sign_public_key, sign_secret_key = sign_algorithm.generate_keypair()
    print(sign_secret_key)
    cert = create_cert(subject,sign_public_key, sign_alg=ALGORITHM["signalgorithm"])


    cert_table.append(cert)
    print(cert)
    
    payload = {
        "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
        "private_key": sign_secret_key
    }
    response_jwt = jwt.encode(payload, CA_sign_secret_key, ALGORITHM["signalgorithm"])
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
                    data_jwt = symmetric_decryption(MainHandler.symmetrical_key, encrypted_data["encrypted_message"])
                    data = jwt.decode(data_jwt, pk)
                    
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
                        pk_hostname = find_public_key(data["hostname"])
                        
                        payload = {
                            "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
                            "public_key" : pk_hostname
                        }
                        response_jwt = jwt.encode(payload, CA_sign_secret_key, ALGORITHM["signalgorithm"])
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
