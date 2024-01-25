from modules import load_config
from modules.communication import send_request, get_sign_private_key

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

NODE, ALGORITHM, CA = load_config('config.ini')

sign_private_key = ""
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
        # zprava
        message = "correct message correct"

        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
            "message": message,
        }

        response = send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="message")
        print(response["message"])

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

    my_address['ip_address'] = "localhost"
    my_address['port'] = port

    sign_private_key = get_sign_private_key(my_address, CA, ALGORITHM)

    tornado.ioloop.IOLoop.current().call_later(1, send_logs)  
    tornado.ioloop.IOLoop.current().start()