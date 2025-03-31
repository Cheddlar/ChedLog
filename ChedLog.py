"""Discord token scanner and decryptor for multiple browsers and applications."""
# pylint: disable=too-many-locals,too-many-branches,too-many-statements,invalid-name
import os
import re
import base64
import json
import requests
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData  # pylint: disable=no-name-in-module
from colorama import Fore, init
import clipboard

init(autoreset=True)

VALID_TOKENS = {}
SEEN_TOKENS = set()

ASCII_ART = r'''
    ___ _              _ _             
  / __\ |__   ___  __| | | ___   __ _ 
 / /  | '_ \ / _ \/ _` | |/ _ \ / _` |
/ /___| | | |  __/ (_| | | (_) | (_| |
\____/|_| |_|\___|\__,_|_|\___/ \__, |
                                |___/ 
'''

print(Fore.RED + ASCII_ART)
print(Fore.WHITE + "=" * 40)
print(Fore.CYAN + "Made by Cheddlar" + Fore.WHITE + " || " + Fore.MAGENTA + "Version: 1.4.5")
print("\n" + Fore.YELLOW + "Initializing token scanner...\n")

def fetch_tokens_and_usernames():
    """Scan browsers and applications for Discord tokens and validate them."""
    regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}|mfa\.[\w-]{84}"
    encrypted_regex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*"
    
    paths = {
        'Discord': os.path.join(
            os.getenv("APPDATA"), 'Discord', 'Local Storage', 'leveldb'
        ),
        'Discord Canary': os.path.join(
            os.getenv("APPDATA"), 'DiscordCanary', 'Local Storage', 'leveldb'
        ),
        'Discord PTB': os.path.join(
            os.getenv("APPDATA"), 'discordptb', 'Local Storage', 'leveldb'
        ),
        'Google Chrome': os.path.join(
            os.getenv("LOCALAPPDATA"), 'Google', 'Chrome', 'User Data',
            'Default', 'Local Storage', 'leveldb'
        ),
        'Chrome Beta': os.path.join(
            os.getenv("LOCALAPPDATA"), 'Google', 'Chrome Beta', 'User Data',
            'Default', 'Local Storage', 'leveldb'
        ),
        'Microsoft Edge': os.path.join(
            os.getenv("LOCALAPPDATA"), 'Microsoft', 'Edge', 'User Data',
            'Default', 'Local Storage', 'leveldb'
        ),
        'Opera': os.path.join(
            os.getenv("APPDATA"), 'Opera Software', 'Opera Stable',
            'Local Storage', 'leveldb'
        ),
        'Opera GX': os.path.join(
            os.getenv("APPDATA"), 'Opera Software', 'Opera GX Stable',
            'Local Storage', 'leveldb'
        ),
        'Brave': os.path.join(
            os.getenv("LOCALAPPDATA"), 'BraveSoftware', 'Brave-Browser',
            'User Data', 'Default', 'Local Storage', 'leveldb'
        ),
        'Yandex': os.path.join(
            os.getenv("LOCALAPPDATA"), 'Yandex', 'YandexBrowser',
            'User Data', 'Default', 'Local Storage', 'leveldb'
        ),
    }

    def decrypt_payload(buff, master_key):
        """Decrypt encrypted token payload using AES-GCM."""
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        except (ValueError, KeyError):
            return None

    def get_decryption_key(path):
        """Retrieve and decrypt master key from browser's local state."""
        try:
            with open(path, "r", encoding='utf-8') as f:
                local_state = json.load(f)
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            return CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None

    def validate_token(tkn, name, printed_apps, token_number):
        """Validate and display token information."""
        if tkn in SEEN_TOKENS:
            return False
        SEEN_TOKENS.add(tkn)

        try:
            response = requests.get(
                "https://discord.com/api/v9/users/@me",
                headers={"Authorization": tkn},
                timeout=10
            )
            if response.status_code == 200:
                user_info = response.json()
                username = user_info['username']
                discrim = user_info['discriminator']
                formatted_name = (f"{username}#{discrim}" 
                                if discrim != "0" else username)
                
                if name not in printed_apps:
                    print(f"\n{Fore.GREEN}[✓] {Fore.WHITE}Valid token #{token_number} "
                        f"found in {Fore.CYAN}{name}")
                    print(f"{Fore.WHITE}    ├─ Account: {Fore.MAGENTA}{formatted_name}")
                    print(f"{Fore.WHITE}    └─ Token: {tkn}")
                    printed_apps.add(name)
                    VALID_TOKENS[token_number] = tkn
                    return True
            return False
        except requests.RequestException:
            return False

    printed_apps = set()
    token_number = 1
    stats = {'found': 0, 'scanned': 0, 'errors': 0}

    print(f"{Fore.BLUE}\n{' SCANNING STARTED ':=^40}\n")

    for name, path in paths.items():
        try:
            if not os.path.exists(path):
                print(f"{Fore.YELLOW}[•] {name.ljust(20)} {Fore.WHITE}→ "
                    f"{Fore.YELLOW}Not installed")
                stats['scanned'] += 1
                continue

            local_state_path = os.path.join(
                os.path.dirname(os.path.dirname(path)), 
                'Local State'
            )
            if not os.path.exists(local_state_path):
                print(f"{Fore.YELLOW}[•] {name.ljust(20)} {Fore.WHITE}→ "
                    f"{Fore.RED}Missing encryption key")
                stats['errors'] += 1
                continue

            dec_key = get_decryption_key(local_state_path)
            if not dec_key:
                print(f"{Fore.YELLOW}[•] {name.ljust(20)} {Fore.WHITE}→ "
                    f"{Fore.RED}Decryption failed")
                stats['errors'] += 1
                continue

            found_tokens = []
            for file in os.listdir(path):
                if not file.endswith(('.log', '.ldb')):
                    continue

                try:
                    with open(os.path.join(path, file), 
                            'r', 
                            errors='ignore', 
                            encoding='utf-8') as f:
                        content = f.read()
                        encrypted_tokens = re.findall(encrypted_regex, content)
                        
                        for encrypted_token in encrypted_tokens:
                            try:
                                encrypted_value = base64.b64decode(
                                    encrypted_token.split('dQw4w9WgXcQ:')[1]
                                )
                                decrypted_token = decrypt_payload(encrypted_value, dec_key)
                                if decrypted_token and re.match(regex, decrypted_token):
                                    found_tokens.append(decrypted_token)
                            except (IndexError, ValueError):
                                continue
                except OSError:
                    continue

            if found_tokens:
                for token in found_tokens:
                    if validate_token(token, name, printed_apps, token_number):
                        stats['found'] += 1
                        token_number += 1
                print(f"{Fore.GREEN}[✓] {name.ljust(20)} {Fore.WHITE}→ "
                    f"{Fore.GREEN}{len(found_tokens)} tokens")
            else:
                print(f"{Fore.YELLOW}[•] {name.ljust(20)} {Fore.WHITE}→ "
                    f"{Fore.YELLOW}No tokens found")

            stats['scanned'] += 1

        except Exception:  # pylint: disable=broad-except
            print(f"{Fore.RED}[!] {name.ljust(20)} {Fore.WHITE}→ {Fore.RED}Scan error")
            stats['errors'] += 1

    print(f"\n{Fore.BLUE}{' SCAN SUMMARY ':=^40}")
    print(f"{Fore.GREEN}✔ Found tokens: {stats['found']}")
    print(f"{Fore.CYAN}➤ Scanned apps: {stats['scanned']}")
    print(f"{Fore.YELLOW}⚠ Errors: {stats['errors']}")

    if VALID_TOKENS:
        while True:
            try:
                choice = input(f"\n{Fore.WHITE}Enter token number to copy "
                            f"(1-{len(VALID_TOKENS)}): ")
                if choice.lower() == "exit":
                    break
                clipboard.copy(VALID_TOKENS[int(choice)])
                print(f"{Fore.GREEN}✓ Token {choice} copied to clipboard!")
                break
            except (ValueError, KeyError):
                print(f"{Fore.RED}⚠ Invalid input. Enter a number or type `exit`.")
    else:
        print(f"\n{Fore.RED}⚠ No valid tokens found.")


if __name__ == '__main__':
    fetch_tokens_and_usernames()
    input(f"\n{Fore.WHITE}Press Enter to exit...")
