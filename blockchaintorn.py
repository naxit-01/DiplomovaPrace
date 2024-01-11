import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

#pip install urllib3 requests

import requests
import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.gen

# https://medium.com/@vanflymen/learn-blockchains-by-building-one-117428612f46
class Blockchain:
    def __init__(self):
        self.current_logs = []
        self.chain = []
        self.nodes = set()

        # Vytvori prvni "genesis" blok, tak aby ty dalsi, ktere uz budou obsahovat zaznamy mely predeslou hash
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        Zjisti jestli je retez validni, to znamena jestli odpovidaji hash jednoho k jeho hodnote v nasledujicim radku

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
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
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

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'logs': self.current_logs,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of logs
        self.current_logs = []

        self.chain.append(block)
        return block

    def new_log(self, public_key, message, signature):
        """
        Creates a new log to go into the next mined Block

        :param public_key: clients public key
        :param message: messsage from a client
        :param signature: signature of the message
        :return: The index of the Block that will hold this log
        """
        self.current_logs.append({
            'public_key': public_key,
            'message': message,
            'signature': signature,
        })

        return self.last_block['index'] + 1

    """@property je vestavěný dekorátor v jazyce Python, který umožňuje definovat metodu jako vlastnost objektu. 
    Vlastnost objektu je atribut, který se chová jako metoda, ale může být přístupný jako atribut. To znamená, 
    že když se na vlastnost odkazuje, volá se metoda, ale když se vlastnost nastavuje, nastavuje se hodnota atributu .

    Vlastnosti jsou užitečné, když chcete, aby se objekt choval jako atribut, ale chcete, 
    aby se při přístupu k němu vykonala určitá akce. Například můžete použít vlastnost k získání nebo nastavení 
    hodnoty atributu, když se k němu přistupuje, nebo k výpočtu hodnoty na základě jiných atributů objektu ."""
    @property
    def last_block(self):
        return self.chain[-1]

    """@staticmethod je vestavěný dekorátor v jazyce Python, který definuje statickou metodu v třídě. 
    Statická metoda je metoda, která je vázána na třídu a ne na objekt třídy. 
    Lze ji volat bez vytvoření instance třídy. Statická metoda neobdrží implicitní první argument, 
    kterým je obvykle self nebo cls. Je přítomna v třídě, protože má smysl pro metodu být v třídě. 
    Statická metoda nepřistupuje k atributům ani nemodifikuje stav třídy"""
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"




# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

class MineHandler(tornado.web.RequestHandler):
    def get(self):
        # We run the proof of work algorithm to get the next proof...
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block)
        

        # We must receive a reward for finding the proof.
        # The sender is "0" to signify that this node has mined a new coin.
        blockchain.new_log(
            public_key="",
            message=f"Blok ukoncil node: {node_identifier}",
            signature="",
        )

        # Forge the new Block by adding it to the chain
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)

        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'logs': block['logs'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        self.write(json.dumps(response))

class New_logHandler(tornado.web.RequestHandler):
    def post(self):
        values = json.loads(self.request.body.decode('utf-8'))

        # Check that the required fields are in the POST'ed data
        required = ['public_key', 'message', 'signature']
        if not all(k in values for k in required):
            return 'Missing values', 400

        # Create a new Log
        index = blockchain.new_log(values['public_key'], values['message'], values['signature'])

        response = {'message': f'Log will be added to Block {index}'}
        self.write(json.dumps(response))

class ChainHandler(tornado.web.RequestHandler):
    def get(self):
        response = {
            'chain': blockchain.chain,
            'length': len(blockchain.chain),
        }
        self.write(json.dumps(response))

class Nodes_registerHandler(tornado.web.RequestHandler):
    def post(self):
        values = json.loads(self.request.body.decode('utf-8'))

        nodes = values.get('nodes')
        if nodes is None:
            return "Error: Please supply a valid list of nodes", 400

        for node in nodes:
            blockchain.register_node(node)

        response = {
            'message': 'New nodes have been added',
            'total_nodes': list(blockchain.nodes),
        }
        self.write(json.dumps(response))

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
    
def make_app():
    return tornado.web.Application([
        (r"/mine", MineHandler),
        (r"/logs/new", New_logHandler),
        (r"/chain", ChainHandler),
        (r"/nodes/resolve", Nodes_resolveHandler),
        (r"/nodes/register", Nodes_registerHandler)
    ])


if __name__ == "__main__":
    app = make_app()
    app.listen(9999)
    print("Tornado server is listening on port 9999")
    #tornado.ioloop.IOLoop.current().call_later(0, print_alive)
    tornado.ioloop.IOLoop.current().start()
