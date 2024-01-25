import configparser
import base64
from secrets import compare_digest
import json
import datetime
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

from modules import get_time, load_config, ask_public_key, get_sign_private_key
from modules import jwt
NODE, ALGORITHM, CA = load_config('config.ini')

from modules.KEMalgorithm import *
from modules.signatures import *

kem_algorithm = globals()[ALGORITHM["kemalgorithm"]]()


from modules.symmetric import symmetric_encryption,symmetric_decryption

my_address = {}

sign_private_key = ""



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
                # Získání těla (body) požadavku
                encrypted_data = self.request.body
                if encrypted_data:
                    # Pokud jsou v těle požadavku nějaká data
                    # print("V těle požadavku jsou data.")
                    encrypted_data=json.loads(encrypted_data.decode())
                    # Najdu si verejny klic v databazi
                    subject = self.request.headers.get('hostname')
                    pk = ask_public_key(subject,sign_private_key, my_address, kem_algorithm, CA, ALGORITHM)
                    data_jwt = symmetric_decryption(MainHandler.symmetrical_key, encrypted_data["encrypted_message"])

                    data = jwt.decode(data_jwt, pk)
                   
                else:
                    # Pokud není v těle požadavku žádná data
                    # print("V těle požadavku nejsou žádná data.")
                    pass
                

                match request:
                    case "message":
                        subject = self.request.headers.get('hostname')
                        print(f"{subject} sent message: {data["message"]}")

                        payload = {
                            "sub" : f"{CA["ca_ip_address"]}:{CA["ca_port"]}",
                            "message" : "thanks"
                        }
                        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
                        response = response_jwt
                        

                # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
                encrypted_response = symmetric_encryption(MainHandler.symmetrical_key, response)
                self.write(json.dumps({"data":encrypted_response}))

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    # Nejprve se pokusim spustit server na portu 8889, bude se mi hodit pro debugovani, pozdeji nebude mit smysl
    port=9999
    try:
        app.listen(port)
        print(f"Server is listening on port 9999")
    except:
        import random
        while True:
            port = random.randint(9991, 9999)
            try:
                app.listen(port)
                print(f"Server is listening on port {port}")
                break
            except: 
                continue

    my_address['ip_address']="localhost"
    my_address['port']=port

    sign_private_key = get_sign_private_key(my_address, CA, kem_algorithm)

    tornado.ioloop.IOLoop.current().start()
