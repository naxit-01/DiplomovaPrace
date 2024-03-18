import hashlib
import json
import time
import asyncio
import random
from collections import Counter
from .utility import get_time

class Blockchain:
    def __init__(self, complexity):
        self.current_logs = []
        self.chain = []
        self.last_block_timestamp = 0.0
        self.ismining = False
        self.isresolving = False
        self.complexity = complexity

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
            #print(f'{last_block}')
            #print(f'{block}')
            #print("\n-----------\n")

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

    async def resolve_conflicts(self, hashes):
        responses = hashes

        # Spočítejte výskyty každého hashe
        hash_counter = Counter(item['hash'] for item in responses)

        # Získání dvou nejvyšších četností
        top_two_counts = hash_counter.most_common(2)

        # Zjistění, zda je nejvyšší prvek nejvyšší absolutně
        if len(top_two_counts) == 2 and top_two_counts[0][1] == top_two_counts[1][1]:
            print("První a druhý nejvyšší prvek mají stejnou četnost, není nejvyšší absolutně.")
            return False, None
        else:
            print("První prvek je nejvyšší absolutně.")
            if top_two_counts[0][0] == self.hash(self.chain): # TODO zmenit na ==
                # My mame spravny chain
                print("my mame spravny chain")
                return True, None
            for response in responses:
                print("Museli jsme chain zmenit")
                if top_two_counts[0][0] == response["hash"]:
                    return False, response
                    
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
        print("validuji block")
        # Nejprve overim zda blok vubec muze byt pridan do retezu, tedy jestli odpovida dukaz
        if self.valid_proof(block): pass # Vse v poradku
        else: 
            print("FalseValidBlock1 - invalid_proof") 
            return False # Block nema spravne vypocitany dukaz, neni platnym blokem

        


        # Tato funkce zkontroluje jestli blok zapada indexove do retezu, pokud ne pokusi se udelat napravu nebo blok zahodi
        last_block = self.chain[-1]
        if block["index"] == last_block["index"]+1:
            if self.hash(last_block) == block["previous_hash"]: return True # Vse  poradku
            else:
                print("FalseValidBlock2 - no_connection[-1]") 
                return False # Block nesplnuje navaznost hashi na sebe, nema hash predesleho blocku

        elif block["index"] == last_block["index"]:
            # V retezci je blok se stejnym indexem. Ocividne doslo ke konfliktu pri posilani tezby   
            if self.last_block_timestamp>=timestamp:
                # Nejprve overim zda blok vubec mohu pridat do retezu, tedy zda previous_hash odpovida hashe z predposledniho bloku
                if self.hash(self.chain[-2]) == block["previous_hash"]:
                    #blok ktery je v retezci byl vytezen pozdeji nez blok, ktery chceme zaradit. Ocividne se jen drive dostal do razeni.
                    # nez blok smazeme tak zaradime vsechny jeho zpravy zpatky do zasobniku. (je dost mozne ze blok, ktery ho vyradil obsahuje stejne zpravy, ale za prve by nam to hodilo chybu a za druhe se to neprojevi, protoze ty jeho zpravy pak stejne budeme mazat)
                    try:
                        logs = self.current_logs  # Uložit aktuální logy do nové proměnné
                        self.current_logs = []  # Vyprázdnit aktuální logy

                        # Převést slovníky na řetězce
                        logs = [json.dumps(item) for item in logs]

                        # Přidat logy z posledního bloku
                        for item in self.chain[-1]["logs"]:
                            logs.append(json.dumps(item))

                        # Odstranit duplikáty a převést zpět na seznam slovníků
                        logs = list(set(logs))
                        logs = [json.loads(item) for item in logs]

                        # Přidat nové logy k aktuálním
                        self.current_logs = self.current_logs + logs

                    except Exception as e: 
                        print(f"error {e}")
                        prom1 = self.chain[-1]["logs"]
                        prom1 = set(prom1)
                        prom2 = self.current_logs
                        prom3 = (prom1.union(prom2))
                        print("error")

                    del self.chain[-1]
                    return True
                else: 
                    print("FalseValidBlock3 - no_connection[-2]") 
                    return False # Neodpovida navaznost hashi
            else: 
                #blok ktery chci priradit byl vytezen pozdeji a proto ho nechci pridat
                print("FalseValidBlock4 - latter") 
                return False
        print("FalseValidBlock4 - what_the_fuck_index")
        return False

    def new_log(self, message):
        """
        Creates a new log to go into the next mined Block

        :param public_key: clients public key
        :param message: messsage from a client
        :param signature: signature of the message
        :return: The index of the Block that will hold this log
        """
        log = {
            'message': message
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

    async def mining(self, block, send_result, seed=None):
        print(f"def mining() is running in the background.")
        self.ismining = True
        #tezba pobezi tak dlouho dokud se ji nezmeni parametr pro beh, nebo dokud nenajde vysledek
        random.seed(seed)
        while self.valid_proof(block) is False:
            if self.isresolving == True:
                self.ismining = False
                print("mining has been stopped by resolving")
                return
            guess = random.randint(0, 100 ** self.complexity)
            block["proof"] = guess
            await asyncio.sleep(0)
        self.ismining = False

        """while self.valid_proof(block) is False:
            block["proof"] += 1
            await asyncio.sleep(0)"""
        
        timestamp = get_time()
        send_result(timestamp)
        

    def valid_proof(self, block):
        """
        Validates the Proof

        :param block
        :return: <bool> True if correct, False if not.

        """
        guess_hash = self.hash(block)

        return guess_hash.startswith("0" * self.complexity)