import os
import subprocess
from typing import Dict, List

import whois


def get_whois(domain: str) -> Dict[str, str]:
    data = whois.whois(domain)

    return data


def resolve_all(OUTPUT_DIR: str, timestamp: str, subdomains_file: str) -> List[str]:
    if not os.path.isdir(f"{OUTPUT_DIR}/resolve/"):
        os.mkdir(f"{OUTPUT_DIR}/resolve/")

    result = subprocess.run(["puredns", 'resolve', subdomains_file,
                             '--resolvers', '/root/wordlists/public_resolvers.txt',
                             '--write-massdns', f'{OUTPUT_DIR}/resolve/massdns_resolve_{timestamp}.txt',
                             '-w', f'{OUTPUT_DIR}/resolve/resolved_subdomains_{timestamp}.txt'
                             ], capture_output=True, text=True)

    with open(f'{OUTPUT_DIR}/resolve/massdns_resolve_{timestamp}.txt') as f:
        resolved_domains = f.read().split('\n')

    return list(filter(None, resolved_domains))


def resolve_list(subdomain_list: List[str], OUTPUT_DIR: str, timestamp: str) -> List[str]:
    if not os.path.isdir(f"{OUTPUT_DIR}/resolve/"):
        os.mkdir(f"{OUTPUT_DIR}/resolve/")
    result = subprocess.run(["puredns", 'resolve',
                             '--resolvers', '/root/wordlists/public_resolvers.txt',
                             '--write-massdns', f'{OUTPUT_DIR}/resolve/massdns_resolve_{timestamp}.txt',
                             '-w', f'{OUTPUT_DIR}/resolve/resolved_subdomains_{timestamp}.txt'
                             ], input='\n'.join(subdomain_list), capture_output=True, text=True)

    with open(f'{OUTPUT_DIR}/resolve/massdns_resolve_{timestamp}.txt') as f:
        resolved_domains = f.read().split('\n')

    return list(filter(None, resolved_domains))
