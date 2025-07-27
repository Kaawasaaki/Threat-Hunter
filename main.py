import argparse
from utils.validate_ioc import identify_ioc
from vt_lookup import lookup_iocs

parser = argparse.ArgumentParser(description="Threat Hunting Automation Tool")
parser.add_argument("--input", required=True, help="Path to IOC input file (e.g., ioc_input.txt)")
args = parser.parse_args()

input_file = args.input

# Read and validate each IOC in the file
with open(input_file, "r") as f:
    iocs = [line.strip() for line in f if line.strip()]

valid_iocs = []
for ioc in iocs:
    ioc_type = identify_ioc(ioc)
    if ioc_type:
        valid_iocs.append((ioc, ioc_type))
    else:
        print(f"[!] Skipping invalid IOC: {ioc}")

if not valid_iocs:
    print(" No valid IOCs found. Exiting.")
    exit(1)

print(f"\n Found {len(valid_iocs)} valid IOCs. Starting lookup...\n")

# Send list to lookup function
lookup_iocs(valid_iocs)
