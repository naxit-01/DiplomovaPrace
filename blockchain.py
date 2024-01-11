import hashlib
import json
import time
from uuid import uuid4
import threading
import asyncio
import random

#pip install urllib3 requests

import requests
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

# https://medium.com/@vanflymen/learn-blockchains-by-building-one-117428612f46

my_address = {"ip_address":"","port":"","node_identifier":""}
node_table = []

def get_time():

    # Získání aktuálního času v nanosekundách
    time_ns = time.time_ns()

    # Převod na čitelný text
    time_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time_ns // 1000000000))

    # Přidání nanosekund do textu
    time_text += f".{time_ns % 1000000000:09d}"

    # Odstranění všech nečíselných znaků z řetězce
    time_digits = "".join(filter(str.isdigit, time_text))

    # Převod na float
    time_float = float(f"{time_digits[:-9]}.{time_digits[-9:]}")

    return time_float

class Blockchain:
    def __init__(self):
        self.current_logs = []
        self.chain = []
        self.nodes = set()
        self.last_block_timestamp = 0.0
        self.ismining = False

        # Vytvori prvni "genesis" blok, tak aby ty dalsi, ktere uz budou obsahovat zaznamy mely predeslou hash
        self.new_block({
            "index": 1,
            "timestamp_start": get_time(),
            "logs": "genesis",
            "proof": 100,
            "previous_hash": "1"
        },get_time())

    def valid_chain(self, chain):
        """
        Zjisti jestli je retez validni, to znamena jestli u kazdeho blocku hash zacina ctyrmi nulami 
        a zaroven jestli se hash nachazi v nasledujicim blocku
        
        vstup: retez
        vystup: True nebo False
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")

            # Check that the Proof of Work is correct
            if not self.valid_proof(block):
                print("Invalid proof")
                return False

            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                print("Invalid: chain hash")
                return False

            

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, block, timestamp):
        # Vytvori novy blok v retezci
        """
        Vytvori novy block v blockchainu

        :param block: novy block, ktery ma byt pridany
        :return: New Block
        """

        self.chain.append(block)

        # Vymaze z currentlogs vsechny zpravy ktere uz byly zapsany do blockchainu
        self.current_logs = [slovnik for slovnik in self.current_logs if slovnik not in block["logs"]]

        self.last_block_timestamp = timestamp

        return block

    def valid_block(self,block,timestamp):
        # Tato funkce zkontroluje jestli blok zapada do retezu, pokud ne pokusi se udelat napravu nebo blok zahodi
        last_block = self.chain[-1]
        if block["index"] == last_block["index"]+1:
            # Vse je jak ma byt
            return True
        elif block["index"] == last_block["index"]:
            # V retezci je blok se stejnym indexem. Ocividne doslo ke konfliktu pri posilani tezby
            if self.last_block_timestamp>=timestamp:
                #blok ktery je v retezci byl vytezen pozdeji nez blok, ktery chceme zaradit. Ocividne se jen drive dostal do razeni.
                del self.chain[-1]
                return True
            else: 
                #blok ktery chci priradit byl vytezen pozdeji a proto ho nechci pridat
                return False
        return False

    def new_log(self, public_key, message, signature):
        """
        Creates a new log to go into the next mined Block

        :param public_key: clients public key
        :param message: messsage from a client
        :param signature: signature of the message
        :return: The index of the Block that will hold this log
        """
        log = {
            'public_key': public_key,
            'message': message,
            'signature': signature,
        }
        if log not in self.current_logs:
            self.current_logs.append(log)
            return True
        return False

    """@property je vestavěný dekorátor v jazyce Python, který umožňuje definovat metodu jako vlastnost objektu. 
    Vlastnost objektu je atribut, který se chová jako metoda, ale může být přístupný jako atribut. To znamená, 
    že když se na vlastnost odkazuje, volá se metoda, ale když se vlastnost nastavuje, nastavuje se hodnota atributu .

    Vlastnosti jsou užitečné, když chcete, aby se objekt choval jako atribut, ale chcete, 
    aby se při přístupu k němu vykonala určitá akce. Například můžete použít vlastnost k získání nebo nastavení 
    hodnoty atributu, když se k němu přistupuje, nebo k výpočtu hodnoty na základě jiných atributů objektu ."""
    @property
    def last_block(self):
        return self.chain[-1]

    def hash(self, block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # Nejprve seradime klice v blocku a pote ho zaheshujeme
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    async def mining(self, block):
        print(f"def mining() is running in the background.")
        self.ismining = True
        #tezba pobezi tak dlouho dokud se ji nezmeni parametr pro beh, nebo dokud nenajde vysledek
        guesses = set()
        random.seed(my_address["node_identifier"])
        while self.valid_proof(block) is False:
            guess = random.randint(0, 100000000)
            guesses.add(guess)
            block["proof"] = guess
            await asyncio.sleep(0)
        self.ismining = False

        """while self.valid_proof(block) is False:
            block["proof"] += 1
            await asyncio.sleep(0)"""
        
        timestamp = get_time()
        print("odesilam")
        for node in node_table:
            # Rekne vsem ze hra skoncila. Posle vsem svuj vytezeny blok
            print(f"zprava pro {node["port"]}")
            url = f"http://{node["ip_address"]}:{node["port"]}/mine/stop"
            await tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps([block,timestamp]))

    def proof_of_work(self, block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        while self.valid_proof(block) is False:
            block["proof"] += 1
        return block["proof"]

    def valid_proof(self, block):
        """
        Validates the Proof

        :param block
        :return: <bool> True if correct, False if not.

        """
        
        guess_hash = self.hash(block)

        return guess_hash[:3] == "000"


# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')
my_address["node_identifier"]=node_identifier

# Instantiate the Blockchain
blockchain = Blockchain()


class MiningHandler(tornado.web.RequestHandler):
    async def get(self, action):
        if action == "start":
            if blockchain.ismining:
                self.write("already mining")
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
            # Overime jestli prave netezime blok, pokud ano jedna se nezadanou aktivitu a nebudeme na ni reagovat
            if blockchain.ismining:
                self.write("already mining")
                return
            # Pridame zaznam o tom kdo dany blok vytezil, neni dulezite pro funkcnost
            blockchain.new_log(
                public_key="",
                message=f"Blok ukoncil node: {my_address["node_identifier"]}",
                signature="",
            )

            # Vypocitam hash z predchoziho bloku
            previous_hash = blockchain.hash(blockchain.last_block)

            block = {
                'index': len(blockchain.chain) + 1,
                'timestamp_start': get_time(),
                'logs': blockchain.current_logs,
                'proof': 0, #bude zmeneno pri proof_of_work
                'previous_hash': previous_hash,
            }

            t = asyncio.create_task(blockchain.mining(block))
            print("mining")
        elif action == "mined":
            values = json.loads(self.request.body.decode('utf-8'))

            # Rekne vsem ze hra skoncila. Posle vsem svuj vytezeny blok
            for node in node_table:
                    url = f"http://{node["ip_address"]}:{node["port"]}/mine/stop"
                    await tornado.httpclient.AsyncHTTPClient().fetch(url, method='POST', body=json.dumps(values))

            # Forge the new Block by adding it to the chain
            block = blockchain.new_block(values)

            response = {
                'message': "New Block Forged",
                'index': block['index'],
                'logs': block['logs'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
            }
            self.write(json.dumps(response))
        elif action == "stop":
            if blockchain.ismining:
                t.cancel()
                blockchain.ismining = False
            self.write("Tornado server has stopped the mining in the background.")

            block, timestamp_end = json.loads(self.request.body.decode('utf-8'))

            if blockchain.valid_block(block, timestamp_end):
                self.write("block is valid")
                # Forge the new Block by adding it to the chain
                block = blockchain.new_block(block, timestamp_end)

                print(f"blockadded\n{blockchain.hash(block)}\n{json.dumps(block)}")
            else:
                self.write("invalid block")

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
    def get(self):
        if blockchain.valid_chain(blockchain.chain):
            response = {
                'chain': blockchain.chain,
                'length': len(blockchain.chain),
            }
            self.write(json.dumps(response))
        else: self.write("Chain is invalid")

class Nodes_resolveHandler(tornado.web.RequestHandler):
    def get(self):
        replaced = blockchain.resolve_conflicts()

        if replaced:
            response = {
                'message': 'Our chain was replaced',
                'new_chain': blockchain.chain
            }
        else:
            response = {
                'message': 'Our chain is authoritative',
                'chain': blockchain.chain
            }

        self.write(json.dumps(response))      

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
        (r"/mine/(start|stop|mined|miner)", MiningHandler),
        (r"/logs/new", New_logHandler),
        (r"/chain", ChainHandler),

        (r"/nodes/resolve", Nodes_resolveHandler),

        (r"/nodes/set_nodetable",Nodes_Set_node_tableHandler),
        (r"/nodes/register_node", Node_Register_nodeHandler),
        (r"/nodes/get_nodetable", Node_Get_node_tableHandler)
    ])

async def register_node_async():
        # Na predem definovany sousedni nod (je jedno, ktery to bude) odeslu svoji registraci

        # Pozdeji bude predelano, v souboru config bude adresa nejblizsiho existujiciho nodu
        ip_address = "localhost"
        port = "9999"

        data = {
        "ip_address": my_address['ip_address'],
        "port": my_address['port'],
        "node_identifier":my_address["node_identifier"]
        }

        # Odeslu svoji registraci na node
        await tornado.httpclient.AsyncHTTPClient().fetch(f"http://{ip_address}:{port}/nodes/register_node", method='POST', body=json.dumps(data))

        # Ziskam od sousedniho nodu aktualni blockchain, tim prepisu ten svuj. Prvni node prepise sam sebe
        blockchain.chain = (json.loads((await tornado.httpclient.AsyncHTTPClient().fetch(f"http://{ip_address}:{port}/chain", method='GET')).body.decode('utf-8')))["chain"]

if __name__ == "__main__":
    app = make_app()
    # Nejprve se pokusim spustit server na portu 9999, bude se mi hodit pro debugovani, pozdeji nebude mit smysl
    port=9999
    try:
        app.listen(port)
        print(f"Blockchain node is listening on port 9999")
    except:
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