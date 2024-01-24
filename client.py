import configparser
import base64
from secrets import compare_digest

from modules import get_time, load_config, create_jwt, check_jwt, read_jwt, get_sign_private_key, define_symmetric_key, ask_public_key

NODE, ALGORITHM, CA = load_config('config.ini')

from modules.KEMalgorithm import *
from modules.signatures import *

kem_algorithm = globals()[ALGORITHM["kemalgorithm"]]()
sign_algorithm = globals()[ALGORITHM["signalgorithm"]]()
sign_private_key = ""
from modules.symmetric import symmetric_encryption, symmetric_decryption

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen
import time
import requests
import json

my_address = {}

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Tornado server is running")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

async def send_logs():
    try:
        #symmetrical_key = define_symmetric_key('http://localhost:8888', kem_algorithm, my_address)
        
        pk = ask_public_key("localhost:8889",sign_private_key, my_address, kem_algorithm, CA, ALGORITHM, sign_algorithm)
        
        symmetrical_key = define_symmetric_key('http://localhost:9999', kem_algorithm, my_address)

        #zprava
        message = "correct message correct"

        # podepsani zpravy pomoci privatniho klice
        #signature = sign_algorithm.sign(sign_private_key, message)

        message ={
            "message":message,
        }
        header,payload,response_jwt = create_jwt(ALGORITHM["signalgorithm"],
                                             f"{my_address["ip_address"]}:{my_address["port"]}",
                                             message, 
                                             sign_algorithm, 
                                             sign_private_key)

        #sifrovani zpravy pomoci symetrickeho klice a posila ji na server
        encrypted_message = symmetric_encryption(symmetrical_key, response_jwt)
        data = {'encrypted_message': encrypted_message}
        headers = {'hostname': f'{my_address["ip_address"]}:{my_address["port"]}', 'request_type': "encrypted_request", 'request':"message"}
        response = requests.post(f"http://{NODE["neighbour_ip_address"]}:{NODE["neighbour_port"]}/", data=json.dumps(data), headers = headers).text
        encrypted_data=json.loads(response)["data"]
        
        # Najdu si verejny klic v databazi
        pk = (ask_public_key(f"{NODE["neighbour_ip_address"]}:{NODE["neighbour_port"]}",sign_private_key, my_address, kem_algorithm, CA, ALGORITHM, sign_algorithm))["public_key"]
        jwt = symmetric_decryption(symmetrical_key, encrypted_data)
        if check_jwt(jwt, pk, sign_algorithm) is True:
            data = read_jwt(jwt)
        print(data[1]["payload"]["message"])

    except Exception as e:
        print(e)

    tornado.ioloop.IOLoop.current().call_later(5, send_logs)


if __name__ == "__main__":
    app = make_app()
    # Nejprve se pokusim spustit server na portu 8889, bude se mi hodit pro debugovani, pozdeji nebude mit smysl
    port=8889
    try:
        app.listen(port)
        print(f"Client is listening on port 8889")
    except:
        import random
        while True:
            port = random.randint(8880, 8889)
            try:
                app.listen(port)
                print(f"Client is listening on port {port}")
                break
            except: 
                continue

    my_address['ip_address']="localhost"
    my_address['port']=port

    sign_private_key = get_sign_private_key(my_address, CA, sign_algorithm, kem_algorithm)

    tornado.ioloop.IOLoop.current().call_later(1, send_logs)  
    tornado.ioloop.IOLoop.current().start()