from pathlib import Path

# Cesta k aktuálnímu adresáři (tam, kde se spouští skript)
current_directory = Path.cwd()

# Cesta k souboru ve stejném adresáři jako skript
file_path = f"{current_directory}\\config.ini"

# Vypsání cesty
print(file_path)