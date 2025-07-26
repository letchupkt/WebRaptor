# Common engine utilities can be placed here
import requests
from colorama import Fore

def make_request(url, method='GET', **kwargs):
    try:
        if method.upper() == 'GET':
            response = requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, **kwargs)
        else:
            return None
        
        return response
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Request failed: {e}{Fore.RESET}")
        return None