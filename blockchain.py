import json
from uuid import uuid4
import asyncio

import requests
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

from modules import blockchain as bch
from modules import get_time, load_config

# pip install urllib3 requests
# https://medium.com/@vanflymen/learn-blockchains-by-building-one-117428612f46

NODE, ALGORITHM = load_config('config.ini')

# Generate a globally unique address for this node
my_address = {
    "ip_address":"",
    "port":"",
    "node_identifier":str(uuid4()).replace('-', '')
    }

node_table = []

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
        global t
        if action == "miner":
            def send_result(timestamp):
                print("odesilam")
                for node in node_table:
                    # Rekne vsem ze hra skoncila. Posle vsem svuj vytezeny blok
                    print(f"zprava pro {node["port"]}")
                    url = f"http://{node["ip_address"]}:{node["port"]}/mine/stop"
                    tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps([block,timestamp]))
            
            # Overime jestli prave netezime blok, pokud ano jedna se nezadanou aktivitu a nebudeme na ni reagovat
            if blockchain.ismining:
                self.write("already mining")
                return
            if blockchain.isresolving:
                self.write("already resolving")
                return
            # Pridame zaznam o tom kdo dany blok vytezil, neni dulezite pro funkcnost
            blockchain.new_log(
                public_key="public",
                message=f"Blok ukoncil node: {my_address["node_identifier"]}!",
                signature="sign",
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

            block, timestamp_end = json.loads(self.request.body.decode('utf-8'))

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
        values = json.loads(self.request.body.decode('utf-8'))
        # Zkontroluje jestli dostal vsechny potrebne data
        required = ['public_key', 'message', 'signature']
        if not all(k in values for k in required):
            self.write("Missing values")
            return
        # Create a new Log
        added = blockchain.new_log(values['public_key'], values['message'], values['signature'])
        if added:
            self.write("Log will be added to Block")
            
            # Posle na vsechny nody krome me
            for node in node_table:
                if (node["ip_address"] == my_address['ip_address'] and node["port"] == my_address["port"]) is False:
                    url = f"http://{node["ip_address"]}:{node["port"]}/logs/new"
                    await tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps(values))
            return 
                    
        else:
            self.write("Already has been added")
            return

class ChainHandler(tornado.web.RequestHandler):
    async def get(self, action):
        if action == "get":
            if blockchain.valid_chain(blockchain.chain):
                response = {
                    'chain': blockchain.chain,
                    'length': len(blockchain.chain),
                }
                self.write(json.dumps(response))
            else: self.write("Chain is invalid")
        
        elif action == "resolve":
            if blockchain.isresolving:
                self.write("already resolving")
                return
            else:
                # Odesle vsem nodum prikaz at zacnou porovnavat retezy, vcetne sebe
                for node in node_table:
                    url = f"http://{node["ip_address"]}:{node["port"]}/chain/resolver"
                    tornado.httpclient.AsyncHTTPClient().fetch(url, method='GET')
                self.write("Nodes have started the resolving in the background.")
                return

        elif action == "resolver":
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
               
class Nodes_Set_node_tableHandler(tornado.web.RequestHandler):
    def post(self):
        # Prijme Node_table a updatuje svoji tabulku
        data = json.loads(self.request.body.decode('utf-8'))
        global node_table
        node_table = data
        print(node_table)
        self.write("Node_table has been edited") 

class Node_Register_nodeHandler(tornado.web.RequestHandler):
    # Prijima registrace od Nodu
    async def post(self):
        values = json.loads(self.request.body.decode('utf-8'))
        # Pridava node do vlastni tabulky
        node_table.append(values)
        self.write("Data added to node_table")

        # Odesle svoji updatovanou tabulku vsem co zna
        for node in node_table:
            url = f"http://{node["ip_address"]}:{node["port"]}/nodes/set_nodetable"
            await tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps(node_table))
        return

class Node_Get_node_tableHandler(tornado.web.RequestHandler):
    def get(self):
        self.write(json.dumps(node_table))

def make_app():
    return tornado.web.Application([
        #(r"/mine", MineHandler),
        (r"/mine/(start|stop|miner)", MiningHandler),
        (r"/logs/new", New_logHandler),
        (r"/chain/(get|resolve|resolver|hash)", ChainHandler),
        (r"/nodes/set_nodetable", Nodes_Set_node_tableHandler),
        (r"/nodes/register_node", Node_Register_nodeHandler),
        (r"/nodes/get_nodetable", Node_Get_node_tableHandler) # Pouze pro rucni kontrolu, jinak se nevyuziva
    ])

async def register_node_async():
        # Na predem definovany sousedni nod (je jedno, ktery to bude) odeslu svoji registraci

        ip_address = NODE["neighbour_ip_address"]
        port = NODE["neighbour_port"]

        data = {
        "ip_address": my_address['ip_address'],
        "port": my_address['port'],
        "node_identifier":my_address["node_identifier"]
        }

        # Odeslu svoji registraci na node
        await tornado.httpclient.AsyncHTTPClient().fetch(f"http://{ip_address}:{port}/nodes/register_node", method='POST', body=json.dumps(data))

        # Ziskam od sousedniho nodu aktualni blockchain, tim prepisu ten svuj. Prvni node prepise sam sebe
        blockchain.chain = (json.loads((await tornado.httpclient.AsyncHTTPClient().fetch(f"http://{ip_address}:{port}/chain/get", method='GET')).body.decode('utf-8')))["chain"]

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

    # Odeslu zadost o registraci do blockchain site
    tornado.ioloop.IOLoop.current().call_later(1, register_node_async)

    tornado.ioloop.IOLoop.current().start()