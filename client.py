import requests

ip_address = input("Enter ip address (or press Enter for localhost): ") or "localhost"
port = input("Enter port (or press Enter for 9999): ") or "9999"

while (True):
    user_input = input("1: get node table \n2: send log \n3: start mining \n4: resolve chains \n5: get chain \n ")
    
    if user_input == "1":
        response = requests.get(f"http://{ip_address}:{port}/nodes/get_nodetable")    
    elif user_input == "2":
        message = input("write message: ")
        data = {
            "message" : message
            }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(f"http://{ip_address}:{port}/logs/new", json=data, headers=headers)
    elif user_input == "3":
        response = requests.get(f"http://{ip_address}:{port}/mine/start")
    elif user_input == "4":
        response = requests.get(f"http://{ip_address}:{port}/chain/resolve")
    elif user_input == "5":
        response = requests.get(f"http://{ip_address}:{port}/chain/get")
    print(response.text)
    