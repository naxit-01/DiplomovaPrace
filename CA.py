import json
from modules import  load_config
from modules import jwt
from modules.KEMalgorithm import *
from modules.signatures import *
from modules.symmetric import symmetric_encryption,symmetric_decryption

from uuid import uuid4
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

NODE, ALGORITHM, CA = load_config('config.ini')
kem_algorithm = globals()[ALGORITHM["kemalgorithm"]](ALGORITHM["kemversion"])
sign_algorithm = globals()[ALGORITHM["signalgorithm"]]()
cert_table = []

CA_sign_public_key, CA_sign_secret_key = sign_algorithm.generate_keypair()

keys_table = {}
com_table = {}
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
    cert = create_cert(subject,sign_public_key, sign_alg=ALGORITHM["signalgorithm"])


    cert_table.append(cert) # upravit neresi pokud se nekdo zaregistruje podruhe
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

class KEMHandler(tornado.web.RequestHandler):
    async def post(self):
        subject = self.request.headers.get('hostname')
        # prijima verejny klic od klienta a vytvori z nej sdilene tajemstvi
        data = json.loads(self.request.body.decode('utf-8')) 
        mode = self.request.headers.get('mode')
        if mode == "ordinary":
            pk = find_public_key(subject)
            data = jwt.decode(data, pk)
        elif mode == "emergency":
            pk = find_public_key(subject)
            if pk != "":
                # Emergency mode je mozne spustit pouze poprve, kdyz druha strana jeste nema podepisovaci klic, ve chvili kdy uz je zaregistrovana, tak veskera komunikace, vcetne KEM algoritmu musi byt podepisovana
                payload = {
                    "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
                    "error" : "invalid mode"
                }
                response_jwt = jwt.encode(payload, CA_sign_secret_key, ALGORITHM["signalgorithm"])
                self.write(response_jwt)
                return

        ciphertext, plaintext_original = kem_algorithm.encrypt(data["public_key"])

        #uklada si symetricky klic
        keys_table[subject]=plaintext_original
        com_id = str(uuid4()).replace('-', '')
        com_table[com_id] = plaintext_original

        # Odesila sdilene tajemstvi
        payload = {
            "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
            "ciphertext" : ciphertext,
            "com_id" : com_id 
        }
        response_jwt = jwt.encode(payload, CA_sign_secret_key, ALGORITHM["signalgorithm"])

        self.write(response_jwt)

class MainHandler(tornado.web.RequestHandler):
    symmetric_key = ""
    async def post(self):
        subject = self.request.headers.get('hostname')
        com_id = self.request.headers.get('com_id')
        encrypted_data = self.request.body
        if encrypted_data:
            # Pokud jsou v těle požadavku nějaká data
            # print("V těle požadavku jsou data.")
            encrypted_data=json.loads(encrypted_data.decode())
            # Najdu si verejny klic v databazi
            pk = find_public_key(subject)
            data_jwt = symmetric_decryption(com_table[com_id], encrypted_data["encrypted_message"])
            data = jwt.decode(data_jwt, pk)

        path = self.request.path
        if path == "/register":
            response_jwt = register(subject)
        elif path == "/public_key":
            pk_hostname = find_public_key(data["hostname"])
                        
            payload = {
                "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
                "public_key" : pk_hostname
            }
            response_jwt = jwt.encode(payload, CA_sign_secret_key, ALGORITHM["signalgorithm"])
        else:
            return 404
        
        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        encrypted_response = symmetric_encryption(com_table[com_id], response_jwt)
        self.write(json.dumps({"data":encrypted_response}))

def make_app():
    return tornado.web.Application([
        (r"/KEM", KEMHandler),
        (r"/.*", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    #app.listen(ca_port)
    app.listen(CA["ca_port"], address=CA["ca_ip_address"])  # Změňte na vaši požadovanou IP adresu
    print(f"CA is running on http://{CA["ca_ip_address"]}:{CA["ca_port"]}")
    tornado.ioloop.IOLoop.current().start()
