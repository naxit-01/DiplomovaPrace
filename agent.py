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

async def send_mess():
    try:        
        # zprava
        message = f"{my_address['ip_address']}:{my_address['port']} correct message correct"

        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
            "message": message,
        }

        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="message")
        print(response["message"])

    except Exception as e:
        print(e)

async def send_logs():
    try:        
        # zprava
        message = f"{my_address['ip_address']}:{my_address['port']} correct message correct"

        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
            "message": message,
        }

        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="logs/new")
        print(response["message"])

    except Exception as e:
        print(e)

async def get_node_table():
    try:        
        # zprava

        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
        }

        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="nodes/get_nodetable")
        print(response["message"])

    except Exception as e:
        print(e)

async def get_chain():
    try:        
        # zprava
        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
        }
        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="chain/get")
        print(response["chain"])

    except Exception as e:
        print(e)

async def start_mining():
    try:        
        # zprava
        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
        }
        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="mine/start")
        print(response["chain"])

    except Exception as e:
        print(e)

async def resolve_chains():
    try:        
        # zprava
        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
        }
        response = await send_request(NODE["neighbour_ip_address"],NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="chain/resolve")
        print(response["chain"])

    except Exception as e:
        print(e)

async def ask():
    user_input = input("0: send message\n1: get node table \n2: send log \n3: start mining \n4: resolve chains \n5: get chain \n ")
    if user_input == "0":
        await send_mess()
    if user_input == "1":
        await get_node_table()
    elif user_input == "2":
        await send_logs()
    elif user_input == "3":
        await start_mining()
    elif user_input == "4":
        await resolve_chains()
    elif user_input == "5":
        await get_chain()

    tornado.ioloop.IOLoop.current().call_later(1, ask)
async def get_sign_pk():
    global sign_private_key
    sign_private_key = await get_sign_private_key(my_address, CA, ALGORITHM)

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

    tornado.ioloop.IOLoop.current().call_later(1, get_sign_pk)
    tornado.ioloop.IOLoop.current().call_later(2, ask)  
    tornado.ioloop.IOLoop.current().start()