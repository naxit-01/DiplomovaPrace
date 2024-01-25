import time

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

import configparser

def load_config(file):
    from pathlib import Path

    # Cesta k aktuálnímu adresáři (tam, kde se spouští skript)
    current_directory = Path.cwd()

    # Cesta k souboru ve stejném adresáři jako skript
    file_path = f"{current_directory}\\config.ini"

    # Vypsání cesty
    print(file_path)
    config = configparser.ConfigParser()
    config.read(file)

    algorithm = {}
    print("\nALGORITHM:")
    for key in config["ALGORITHM"]:
        algorithm[key] = config['ALGORITHM'][key]
        print(f"{key} = {config['ALGORITHM'][key]}")

    node = {}
    print("\nNODE:")
    for key in config["NODE"]:
        node[key] = config['NODE'][key]
        print(f"{key} = {config['NODE'][key]}")

    ca = {}
    print("\nCA:")
    for key in config["CA"]:
        ca[key] = config['CA'][key]
        print(f"{key} = {config['CA'][key]}")

    return node, algorithm, ca