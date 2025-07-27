import re

def identify_ioc(ioc: str):
    ioc = ioc.strip().lower()

    # IP Address (IPv4 only)
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Domain (supports subdomains and TLDs like .co.uk)
    domain_regex = r"^(?=.{4,253}$)(?!\-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$"

    # File Hash: MD5 (32), SHA1 (40), SHA256 (64)
    hash_regex = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"

    if re.match(ip_regex, ioc):
        return "ip"
    elif re.match(domain_regex, ioc):
        return "domain"
    elif re.match(hash_regex, ioc):
        return "hash"
    else:
        return None
