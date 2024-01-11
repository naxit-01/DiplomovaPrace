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

from modules.KEMalgorithm import *
from modules.signatures import *

kem_algorithm = globals()[kemalgorithm]()
sign_algorithm = globals()[signalgorithm]()

from modules.symmetric import symmetric_encryption,symmetric_decryption

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen
import json


class MainHandler(tornado.web.RequestHandler):
    symmetrical_key = ""
    def get(self):
        self.write("Tornado server is running")

    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        match data["message_type"]:
            case "KEM_public_key":
                # prijima verejny klic od klienta a vytvori z nej sdilene tajemstvi
                ciphertext, plaintext_original = kem_algorithm.encrypt(data["public_key"])

                #uklada si symetricky klic
                MainHandler.symmetrical_key=plaintext_original

                # odesila sdilene tajemstvi
                response = {
                    "ciphertext":ciphertext
                }
                self.write(json.dumps(response))
                
            case "encrypted_message":
                # prijima zasifrovanou zpravu a pomoci symetrickeho klice ji desifruje
                decrypted_data = symmetric_decryption(MainHandler.symmetrical_key, data["encrypted_message"])
                signed_data = json.loads(decrypted_data)

                # overeni podpisu pomoci prijateho podpisoveho verejneho klice
                if sign_algorithm.verify(signed_data["public_key"],signed_data["message"],signed_data["signature"]):
                    print(signed_data["message"])
                    self.write("thanks")
                else:
                    self.write("invalid signature")
            case 2:
                return "dva"
            case _:
                print("inc")
                self.write("incorrect values")        

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

def print_alive():
    print("I am alive")
    tornado.ioloop.IOLoop.current().call_later(5, print_alive)


if __name__ == "__main__":
    app = make_app()
    app.listen(9999)
    print("Tornado server is listening on port 9999")
    #tornado.ioloop.IOLoop.current().call_later(0, print_alive)
    tornado.ioloop.IOLoop.current().start()


