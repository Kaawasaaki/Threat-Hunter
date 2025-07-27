import requests
import os
import json
import time
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY
}

def lookup_iocs(valid_ioc_list):
    if not os.path.exists("results"):
        os.makedirs("results")

    results = {}

    for ioc, ioc_type in valid_ioc_list:
        print(f" Looking up {ioc} ({ioc_type})...")

        if ioc_type == "ip":
            url = f"{VT_BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{VT_BASE_URL}/domains/{ioc}"
        elif ioc_type == "hash":
            url = f"{VT_BASE_URL}/files/{ioc}"
        else:
            print(f"[!] Unknown IOC type for {ioc}, skipping.")
            continue

        try:
            response = requests.get(url, headers=HEADERS)

            if response.status_code == 200:
                results[ioc] = response.json()
            else:
                results[ioc] = {"error": f"Status code {response.status_code}", "detail": response.text}

        except Exception as e:
            results[ioc] = {"error": str(e)}

        time.sleep(15)  # Rate limiting for free VT API

    # Save output
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_path = f"results/report_{timestamp}.json"

    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nReport saved to: {output_path}")