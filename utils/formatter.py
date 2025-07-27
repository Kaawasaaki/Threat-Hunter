import json
from colorama import Fore, Style

def pretty_print(title, data):
    print(f"\n{Fore.CYAN}[{title}]{Style.RESET_ALL}")
    print("-" * 60)
    print(json.dumps(data, indent=2))