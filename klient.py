import socket

# Vytvoření socketu
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Nastavení IP adresy a portu serveru
server_address = ('localhost', 9999)
s.connect(server_address)

try:
    # Odeslání dat serveru
    message = 'Toto je zpráva. Bude opakována.'
    print(f'Odesílání: {message}')
    s.sendall(message.encode('utf-8'))

    # Přijetí odpovědi od serveru
    data = s.recv(1024)
    print(f'Přijatá: {data.decode("utf-8")}')

finally:
    # Uzavření spojení
    s.close()
