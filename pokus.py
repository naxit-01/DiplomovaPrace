import socket
import time
import threading
import json
# Vytvoření socketu
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Nastavení IP adresy a portu
server_address = ('localhost', 9999)
s.bind(server_address)

# Naslouchání příchozím spojením
s.listen(1)

def print_hello():
    while True:
        # Každých 5 vteřin vypíše "hello"
        
        # Vytvoření socketu
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Nastavení IP adresy a portu serveru
        server_address = ('localhost', 9999)
        s.connect(server_address)

        try:
            #Diffie-Helman
            #Iam Alice
            # Alice generates a (public, secret) key pair
            public_key, secret_key = ["public_key", "secret"]
            print(f'KLIENT: Odesílání: {public_key}')
            import json
            data = json.dumps({"public_key": public_key})
            s.sendall(data.encode('utf-8'))


            # Přijetí odpovědi od serveru
            ciphertext = s.recv(1024)
            print(f'KLIENT: Přijatá: {ciphertext.decode("utf-8")}')

            # Alice decrypts Bob's ciphertext to derive the now shared secret
            plaintext_recovered = secret_key + ciphertext.decode("utf-8")
            
            
            # Odeslání dat serveru
            message = 'Toto je zpráva. Bude opakována.'
            print(f'KLIENT: Odesílání: {message}')
            s.sendall(message.encode('utf-8'))

            # Přijetí odpovědi od serveru
            data = s.recv(1024)
            print(f'KLIENT: Přijatá: {data.decode("utf-8")}')

        finally:
            # Uzavření spojení
            s.close()
        time.sleep(5)

# Spustí funkci print_hello v samostatném vlákně
threading.Thread(target=print_hello).start()

while True:
    # Čekání na spojení
    print('Čekání na připojení...')
    connection, client_address = s.accept()

    try:
        print('SERVER: Spojení z', client_address)

        # Přijímání dat a odesílání odpovědi
        while True:
            data = connection.recv(1024)
            if data:
                import json
                try:
                    data_received = json.loads(data.decode('utf-8'))
                    if 'public_key' in data_received:
                        print(f"public_key = {data_received['public_key']}")
                    else:
                        print("Dostali jsme jinou zprávu")
                except json.JSONDecodeError:
                    print("Dostali jsme jinou zprávu")
                
                print('SERVER: Přijatá data: {!r}'.format(data))
                print('SERVER: Odesílání dat zpět klientovi')

                connection.sendall(data)
            else:
                print('SERVER: Žádná data od', client_address)
                break

    finally:
        # Uzavření spojení
        connection.close()
