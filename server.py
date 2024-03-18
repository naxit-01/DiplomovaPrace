import json
from modules import load_config
from modules import jwt
from modules.KEMalgorithm import *
from modules.symmetric import symmetric_encryption,symmetric_decryption
from modules.communication import ask_public_key, get_sign_private_key

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

NODE, ALGORITHM, CA = load_config('config.ini')
kem_algorithm = globals()[ALGORITHM["kemalgorithm"]]()
my_address = {}
sign_private_key = ""
keys_table = {}

class KEMHandler(tornado.web.RequestHandler):
    async def post(self):
        # prijima verejny klic od klienta a vytvori z nej sdilene tajemstvi
        data = json.loads(self.request.body.decode('utf-8'))     
        subject = self.request.headers.get('hostname')
        mode = self.request.headers.get('mode')
        if mode == "ordinary":
            # Server prijima pouze podepsane pozadavky na KEM algoritmus
            pk = await ask_public_key(subject, sign_private_key, my_address, CA, ALGORITHM)
            data = jwt.decode(data, pk)
        else:
            payload = {
                "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
                "error" : "invalid mode"
            }
            response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
            self.write(response_jwt)
            return

        ciphertext, plaintext_original = kem_algorithm.encrypt(data["public_key"])

        #uklada si symetricky klic
        keys_table[subject]=plaintext_original

        # Odesila sdilene tajemstvi
        payload = {
            "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
            "ciphertext" : ciphertext
        }
        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])

        self.write(response_jwt)

class MainHandler(tornado.web.RequestHandler):
    async def post(self):
        path = self.request.path
        if path == "/message":
            subject = self.request.headers.get('hostname')
            # Získání těla (body) požadavku
            encrypted_data = self.request.body
            if encrypted_data:
                # Pokud jsou v těle požadavku nějaká data tak je desifruji a overim jejich pravost
                encrypted_data = json.loads(encrypted_data.decode())
                
                data_jwt = symmetric_decryption(keys_table[subject], encrypted_data["encrypted_message"])
                pk = await ask_public_key(subject,sign_private_key, my_address, CA, ALGORITHM)
                    
                data = jwt.decode(data_jwt, pk)

            print(f"{subject} sent message: {data["message"]}")

            payload = {
                "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
                "message" : "thanks"
            }
            response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
            response = response_jwt
                        

        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        encrypted_response = symmetric_encryption(keys_table[subject], response)
        self.write(json.dumps({"encrypted_message":encrypted_response}))

async def get_sign_pk():
    global sign_private_key
    sign_private_key = await get_sign_private_key(my_address, CA, ALGORITHM)

def make_app():
    return tornado.web.Application([
        (r"/KEM", KEMHandler),
        (r"/.*", MainHandler),
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

    
    tornado.ioloop.IOLoop.current().call_later(1, get_sign_pk)

    tornado.ioloop.IOLoop.current().start()
