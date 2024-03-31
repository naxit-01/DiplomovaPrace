import requests
import random

ip_address = input("Enter ip address (or press Enter for localhost): ") or "localhost"
port = input("Enter port (or press Enter for 9999): ") or "9999"

while (True):
    user_input = input("1: get node table \n2: send log \n3: start mining \n4: resolve chains \n5: get chain \n ")
    
    if user_input == "1":
        response = requests.get(f"http://{ip_address}:{port}/nodes/get_nodetable")    
    elif user_input == "2":
        def read_random_line(file_path):
            with open(file_path, 'r', encoding='utf-8') as file:
                # Count the total number of lines in the file
                total_lines = sum(1 for line in file)

                # Generate a random line number
                random_line_number = random.randint(1, total_lines)

                # Seek to the random line number
                file.seek(0)
                for _ in range(random_line_number - 1):
                    file.readline()

                # Read and return the random line
                random_line = file.readline().strip()
                return random_line

        message = input("Enter message (or press Enter for default): ") or read_random_line('Windows_2k.log')
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
    