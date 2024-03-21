from modules.KEMalgorithm import *
from modules.symmetric import symmetric_encryption,symmetric_decryption

import json
from uuid import uuid4
import asyncio

import requests
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

from modules.communication import ask_public_key, send_request, send_request_without_response, get_sign_private_key
from modules import jwt
from modules import blockchain as bch
from modules import get_time, load_config

# pip install urllib3 requests
# https://medium.com/@vanflymen/learn-blockchains-by-building-one-117428612f46

NODE, ALGORITHM, CA = load_config('config.ini')
kem_algorithm = globals()[ALGORITHM["kemalgorithm"]]()
sign_private_key = ""
keys_table = {}

# Generate a globally unique address for this node
my_address = {
    "ip_address":"",
    "port":"",
    "node_identifier":str(uuid4()).replace('-', '')
    }

node_table = []
keys_table = {}

# Instantiate the Blockchain
blockchain = bch.Blockchain(int(NODE["complexity"]))


class MiningHandler(tornado.web.RequestHandler):
    async def get(self, action):
        if action == "start":
            if blockchain.ismining:
                self.write("already mining")
                return
            if blockchain.isresolving:
                self.write("already resolving")
                return
            else:
                # Odesle vsem nodum prikaz at zacnou tezit, vcetne sebe
                for node in node_table:
                    url = f"http://{node["ip_address"]}:{node["port"]}/mine/miner"
                    tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps({"miner":"start"}))
                self.write("Nodes have started the mining in the background.")
                return
    
    async def post(self, action):
        if action == "start":
            if blockchain.ismining:
                self.write("already mining")
                return
            if blockchain.isresolving:
                self.write("already resolving")
                return
            else:
                # Odesle vsem nodum prikaz at zacnou tezit, vcetne sebe
                for node in node_table:
                    url = f"http://{node["ip_address"]}:{node["port"]}/mine/miner"
                    tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps({"miner":"start"}))
                response = "Nodes have started the mining in the background."
                payload = {
                    "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
                    "message" : response
                }
                response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
                response = response_jwt
                        

            # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
            subject = self.request.headers.get('hostname')
            encrypted_response = symmetric_encryption(keys_table[subject], response)
            self.write(json.dumps({"encrypted_message":encrypted_response}))
        global t
        if action == "miner":
            async def send_result(timestamp):
                print("odesilam")
                for node in node_table:
                    # Rekne vsem ze hra skoncila. Posle vsem svuj vytezeny blok
                    print(f"zprava pro {node["port"]}")
                    payload ={
                        "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
                        "body":json.dumps([block,timestamp])
                    }

                    await send_request_without_response(node["ip_address"],node["port"], payload, sign_private_key, my_address, CA, ALGORITHM, uri="mine/stop")
                    
                    #url = f"http://{node["ip_address"]}:{node["port"]}/mine/stop"
                    #tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps([block,timestamp]))
            
            # Overime jestli prave netezime blok, pokud ano jedna se nezadanou aktivitu a nebudeme na ni reagovat
            if blockchain.ismining:
                self.write("already mining")
                return
            if blockchain.isresolving:
                self.write("already resolving")
                return
            # Pridame zaznam o tom kdo dany blok vytezil, neni dulezite pro funkcnost
            blockchain.new_log(
                message=f"Blok ukoncil node: {my_address["node_identifier"]}!",
            )

            # Vypocitam hash z predchoziho bloku
            previous_hash = blockchain.hash(blockchain.last_block)

            block = {
                'index': len(blockchain.chain) + 1,
                'timestamp_start': get_time(),
                'logs': blockchain.current_logs,
                'proof': 0, #bude zmeneno pri tezbe
                'previous_hash': previous_hash,
            }

            t = asyncio.create_task(blockchain.mining(block, send_result, seed=my_address["node_identifier"]))
            print("mining")
    
        elif action == "stop":
            if blockchain.ismining:
                # Pokud zprava neprisla ode me, tak jeste tezim. To znamena ze nekdo byl rychlejsi a ja uz tezit nemusim.
                t.cancel()
                await asyncio.sleep(0)
                blockchain.ismining = False
            self.write("Tornado server has stopped the mining in the background.")

            subject = self.request.headers.get('hostname')
            # Získání těla (body) požadavku
            encrypted_data = self.request.body
            if encrypted_data:
                # Pokud jsou v těle požadavku nějaká data tak je desifruji a overim jejich pravost
                encrypted_data = json.loads(encrypted_data.decode())
                
                data_jwt = symmetric_decryption(keys_table[subject], encrypted_data["encrypted_message"])
                pk = await ask_public_key(subject,sign_private_key, my_address, CA, ALGORITHM)
                    
                data = jwt.decode(data_jwt, pk)
            block, timestamp_end = json.loads(data["body"])

            if blockchain.valid_block(block, timestamp_end):
                self.write("block is valid")
                # Forge the new Block by adding it to the chain
                block = blockchain.new_block(block, timestamp_end)

                #print(f"blockadded\n{blockchain.hash(block)}\n{json.dumps(block)}")
            else:
                self.write("invalid block")
            await tornado.httpclient.AsyncHTTPClient().fetch(f'http://{my_address["ip_address"]}:{my_address["port"]}/mine/start', method='GET')

class New_logHandler(tornado.web.RequestHandler):
    async def post(self):
        subject = self.request.headers.get('hostname')
        # Získání těla (body) požadavku
        encrypted_data = self.request.body
        if encrypted_data:
            # Pokud jsou v těle požadavku nějaká data tak je desifruji a overim jejich pravost
            encrypted_data = json.loads(encrypted_data.decode())
                
            data_jwt = symmetric_decryption(keys_table[subject], encrypted_data["encrypted_message"])
            pk = await ask_public_key(subject,sign_private_key, my_address, CA, ALGORITHM)
                    
            data = jwt.decode(data_jwt, pk)

        # Zkontroluje jestli dostal vsechny potrebne data
        if not "message" in data:
            response = "Missing values"
        else:

            # Create a new Log
            #added = blockchain.new_log(values['public_key'], values['message'], values['signature'])
            added = blockchain.new_log(data['message'])
            if added:
                response = "Log will be added to Block"
            
                # Posle na vsechny nody krome me
                for node in node_table:
                    if (node["ip_address"] == my_address['ip_address'] and node["port"] == my_address["port"]) is False:
                        # zprava
                        message = data["message"]
                        payload ={
                            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
                            "message": message,
                        }
                        await send_request(node["ip_address"], node["port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="logs/new")                         
            else:
                response = "Already has been added"
            
        payload = {
            "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
            "message" : response
        }
        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
        response = response_jwt

        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        encrypted_response = symmetric_encryption(keys_table[subject], response)
        self.write(json.dumps({"encrypted_message":encrypted_response}))

class ChainHandler(tornado.web.RequestHandler):
    async def get(self, action):

        if action == "resolver":
            """
            Tento algoritmus vyhodnoti, ktery retez ma majoritni zastoupeni a tento retez pak zvoli za vlastni.

            :return: True if our chain was replaced, False if not
            """
            
            blockchain.isresolving = True

            while blockchain.ismining: 
                #pockam nez dobehne tezba
                await asyncio.sleep(0.5)
            await asyncio.sleep(2)
            
            # Ziska hashe retezu od vsech nodu 
            hashes = []
            for node in node_table:
                response = await tornado.httpclient.AsyncHTTPClient().fetch(f'http://{node["ip_address"]}:{node["port"]}/chain/hash', method='GET')
                hashes.append({"hash":response.body.decode(),"ip_address":node["ip_address"],"port":node["port"]})

            

            correctness_chain, correct_node = await blockchain.resolve_conflicts(hashes)

            if correctness_chain:
                response = {
                    'message': 'Our chain is authoritative',
                    'chain': blockchain.chain,
                    'hash_chain': blockchain.hash(blockchain.chain)
                }
            else:
                if correct_node is not None:
                    blockchain.chain = (json.loads((await tornado.httpclient.AsyncHTTPClient().fetch(f'http://{correct_node["ip_address"]}:{correct_node["port"]}/chain/get', method='GET')).body.decode('utf-8')))["chain"]
                    response = {
                        'message': 'Our chain was replaced',
                        'new_chain': blockchain.chain,
                        'hash_chain': blockchain.hash(blockchain.chain)
                    }
                else:
                    response = {
                        'message': 'Irreparable collision in chains',
                        'new_chain': blockchain.chain,
                        'hash_chain': blockchain.hash(blockchain.chain)
                    }


            #self.write(json.dumps(response))  

            blockchain.isresolving = False # Opet zapnu moznost tezby
            
        elif action == "hash":
            self.write(blockchain.hash(blockchain.chain)) 

    async def post(self, action):
        if action == "get":
            subject = self.request.headers.get('hostname')
            if blockchain.valid_chain(blockchain.chain):
                response = {
                    'chain': blockchain.chain,
                    'length': len(blockchain.chain),
                }
                response = json.dumps(response)
            else: response = "Chain is invalid"
            payload = {
                "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
                "chain" : response
            }
            response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
            response = response_jwt
            
            # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
            
            encrypted_response = symmetric_encryption(keys_table[subject], response)
            self.write(json.dumps({"encrypted_message":encrypted_response}))

        elif action == "resolve":
            if blockchain.isresolving:
                response = "already resolving"
                return
            else:
                # Odesle vsem nodum prikaz at zacnou porovnavat retezy, vcetne sebe
                for node in node_table:
                    url = f"http://{node["ip_address"]}:{node["port"]}/chain/resolver"
                    tornado.httpclient.AsyncHTTPClient().fetch(url, method='GET')
                response = "Nodes have started the resolving in the background."
            payload = {
                "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
                "chain" : response
            }
            response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
            response = response_jwt
            
            # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
            subject = self.request.headers.get('hostname')
            encrypted_response = symmetric_encryption(keys_table[subject], response)
            self.write(json.dumps({"encrypted_message":encrypted_response}))

class Nodes_Set_node_tableHandler(tornado.web.RequestHandler):
    async def post(self):
        # Prijme Node_table a updatuje svoji tabulku
        subject = self.request.headers.get('hostname')
        # Získání těla (body) požadavku
        encrypted_data = self.request.body
        if encrypted_data:
            # Pokud jsou v těle požadavku nějaká data tak je desifruji a overim jejich pravost
            encrypted_data = json.loads(encrypted_data.decode())
                
            data_jwt = symmetric_decryption(keys_table[subject], encrypted_data["encrypted_message"])
            pk = await ask_public_key(subject,sign_private_key, my_address, CA, ALGORITHM)
                    
            data = jwt.decode(data_jwt, pk)

        global node_table
        node_table = json.loads(data["node_table"])
        print(node_table)

        response = "Node_table has been edited"

        payload = {
            "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
            "message" : response
        }
        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
        response = response_jwt

        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        encrypted_response = symmetric_encryption(keys_table[subject], response)
        self.write(json.dumps({"encrypted_message":encrypted_response}))

class Node_Register_nodeHandler(tornado.web.RequestHandler):
    # Prijima registrace od Nodu
    async def post(self):
        subject = self.request.headers.get('hostname')
        # Získání těla (body) požadavku
        encrypted_data = self.request.body
        if encrypted_data:
            # Pokud jsou v těle požadavku nějaká data tak je desifruji a overim jejich pravost
            encrypted_data = json.loads(encrypted_data.decode())
                
            data_jwt = symmetric_decryption(keys_table[subject], encrypted_data["encrypted_message"])
            pk = await ask_public_key(subject,sign_private_key, my_address, CA, ALGORITHM)
                    
            data = jwt.decode(data_jwt, pk)

        # Pridava node do vlastni tabulky
        node_table.append(data["data"])
        response = "Data added to node_table"

        # Odesle svoji updatovanou tabulku vsem co zna
        for node in node_table:
            if (node["ip_address"] == my_address['ip_address'] and node["port"] == my_address["port"]) is False:
                payload ={
                    "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
                    "node_table": json.dumps(node_table),
                }
                await send_request(node["ip_address"], node["port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="nodes/set_nodetable")
        payload = {
            "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
            "message" : response
        }
        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
        response = response_jwt
                        
        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        encrypted_response = symmetric_encryption(keys_table[subject], response)
        self.write(json.dumps({"encrypted_message":encrypted_response}))

class Node_Get_node_tableHandler(tornado.web.RequestHandler):
    def post(self):
        response = json.dumps(node_table)
        payload = {
            "sub" : f"{my_address["ip_address"]}:{my_address["port"]}",
            "message" : response
        }
        response_jwt = jwt.encode(payload, sign_private_key, ALGORITHM["signalgorithm"])
        response = response_jwt
                        
        # Mam zpravu a musim ji ted zasifrovat pomoci symetrickeho klice
        subject = self.request.headers.get('hostname')
        encrypted_response = symmetric_encryption(keys_table[subject], response)
        self.write(json.dumps({"encrypted_message":encrypted_response}))

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

def make_app():
    return tornado.web.Application([
        #(r"/mine", MineHandler),
        (r"/mine/(start|stop|miner)", MiningHandler),
        (r"/logs/new", New_logHandler),
        (r"/chain/(get|resolve|resolver|hash)", ChainHandler),
        (r"/nodes/set_nodetable", Nodes_Set_node_tableHandler),
        (r"/nodes/register_node", Node_Register_nodeHandler),
        (r"/nodes/get_nodetable", Node_Get_node_tableHandler), # Pouze pro rucni kontrolu, jinak se nevyuziva
        (r"/KEM", KEMHandler)
    ])

async def get_sign_pk():
    global sign_private_key
    sign_private_key = await get_sign_private_key(my_address, CA, ALGORITHM)

async def register_node_async():
        # Na predem definovany sousedni nod (je jedno, ktery to bude) odeslu svoji registraci
        data = {
        "ip_address": my_address['ip_address'],
        "port": my_address['port'],
        "node_identifier":my_address["node_identifier"]
        }

        # Odeslu svoji registraci na node
        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
            "data": data,
        }
        await send_request(NODE["neighbour_ip_address"], NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="nodes/register_node")

        # Ziskam od sousedniho nodu aktualni blockchain, tim prepisu ten svuj. Prvni node prepise sam sebe
        payload ={
            "sub":f"{my_address["ip_address"]}:{my_address["port"]}",
        }
        response = await send_request(NODE["neighbour_ip_address"], NODE["neighbour_port"], payload, sign_private_key, my_address, CA, ALGORITHM, request="chain/get")


        blockchain.chain = (json.loads((response)["chain"]))["chain"]

if __name__ == "__main__":
    app = make_app()
    # Nejprve se pokusim spustit server na portu 9999, bude se mi hodit pro debugovani, pozdeji nebude mit smysl
    port=9999
    try:
        app.listen(port)
        print(f"Blockchain node is listening on port 9999")
    except:
        import random
        while True:
            port = random.randint(9991, 9999)
            try:
                app.listen(port)
                print(f"Blockchain node is listening on port {port}")
                break
            except: 
                continue

    my_address['ip_address']="localhost"
    my_address['port']=port
    my_address['node_identifier']=my_address["ip_address"]+":"+str(my_address["port"])+"_"+my_address["node_identifier"]

    tornado.ioloop.IOLoop.current().call_later(1, get_sign_pk)
    # Odeslu zadost o registraci do blockchain site
    tornado.ioloop.IOLoop.current().call_later(2, register_node_async)

    tornado.ioloop.IOLoop.current().start()