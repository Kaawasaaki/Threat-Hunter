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


import requests
import os
import json
import time
import csv
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
        print(f"🔎 Looking up {ioc} ({ioc_type})...")

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
                results[ioc] = {
                    "error": f"Status code {response.status_code}",
                    "detail": response.text
                }

        except Exception as e:
            results[ioc] = {"error": str(e)}

        time.sleep(15)  # Free VT API rate limit

    # Save raw JSON report
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = f"results/report_{timestamp}.json"

    with open(json_path, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n JSON Report saved to: {json_path}")

    # ---  CSV Export ---
    csv_path = f"results/report_{timestamp}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["IOC", "Type", "Malicious", "Suspicious", "Harmless", "Undetected", "VT Link"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for ioc, ioc_type in valid_ioc_list:
            data = results.get(ioc, {})
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_link = f"https://www.virustotal.com/gui/search/{ioc}"

            writer.writerow({
                "IOC": ioc,
                "Type": ioc_type,
                "Malicious": stats.get("malicious", "N/A"),
                "Suspicious": stats.get("suspicious", "N/A"),
                "Harmless": stats.get("harmless", "N/A"),
                "Undetected": stats.get("undetected", "N/A"),
                "VT Link": vt_link
            })

    print(f" CSV Summary saved to: {csv_path}")

    # --- Score Summary ---
    total = len(results)
    malicious = 0
    suspicious = 0

    for ioc, data in results.items():
        try:
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                malicious += 1
            elif stats.get("suspicious", 0) > 0:
                suspicious += 1
        except:
            continue

    print("\n Threat Summary:")
    print(f"Total IOCs Analyzed : {total}")
    print(f"Malicious IOCs      : {malicious}")
    print(f"Suspicious IOCs     : {suspicious}")
    print(f"Clean/Unknown IOCs  : {total - malicious - suspicious}")
    print("\n For detailed analysis, check the JSON and CSV reports in the 'results' folder.")