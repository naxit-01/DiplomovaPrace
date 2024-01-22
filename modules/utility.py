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

    print("\nROLE:")
    for key in config["ROLE"]:
        globals()[key] = config['ROLE'][key]
        print(f"{key} = {config['ROLE'][key]}")

    algorithm = {}
    print("\nalgorithm:")
    for key in config["algorithm"]:
        algorithm[key] = config['algorithm'][key]
        #globals()[key] = config['algorithm'][key]
        print(f"{key} = {config['algorithm'][key]}")

    node = {}
    print("\nNODE:")
    for key in config["NODE"]:
        node[key] = config['NODE'][key]
        #globals()[key] = config['NODE'][key]
        print(f"{key} = {config['NODE'][key]}")

    return node, algorithm
    