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

cipheralgorithm = globals()[cipheralgorithm]()

from modules.symmetric import symmetric_encryption,symmetric_decryption


'''# Alice generates a (public, secret) key pair
public_key, secret_key = cipheralgorithm.generate_keypair()


# Bob derives a secret (the plaintext) and encrypts it with Alice's public key to produce a ciphertext
ciphertext, plaintext_original = cipheralgorithm.encrypt(public_key)

# Alice decrypts Bob's ciphertext to derive the now shared secret
plaintext_recovered = cipheralgorithm.decrypt(secret_key, ciphertext)

if compare_digest(plaintext_original, plaintext_recovered):
    symetrical_key = plaintext_original'''


import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen
import time

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Tornado server is running")


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

def send_logs():
    
    public_key, secret_key = cipheralgorithm.generate_keypair()

    import requests
    import json
    try:
        url = 'http://localhost:9999'
        data = {'message_type':"KEM_public_key",'public_key': public_key}
        #odesilam svuj public key na server a ziskavam cipher text
        response = json.loads(requests.post(url, data=json.dumps(data)).text)

        #ze sdileneho tajemstvi a privatniho klice ziskava symetricky klic
        ciphertext=response["ciphertext"]
        plaintext_recovered = cipheralgorithm.decrypt(secret_key, ciphertext)
        symmetrical_key = plaintext_recovered

        #sifrije zpravu pomoci symetrickeho klice a posila ji na server
        encrypted_message = symmetric_encryption(symmetrical_key, "correct message correct")
        data = {'message_type':"encrypted_message",'encrypted_message': encrypted_message}
        response = requests.post(url, data=json.dumps(data)).text

        print(response)
    except Exception as e:
        print(e)

    tornado.ioloop.IOLoop.current().call_later(5, send_logs)


if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    print("Tornado server is listening on port 8888")
    tornado.ioloop.IOLoop.current().call_later(0, send_logs)
    tornado.ioloop.IOLoop.current().start()
