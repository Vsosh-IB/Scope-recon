from subprocess import run
from typing import List

import fofa

OUTPUT_DIR = "/mnt/output"


def fofa_query(hash: int, API_key: str):
    client = fofa.Client(API_key)
    query_str = f'icon_hash="{hash}"'
    found_domains = []

    for page in range(1, 21):
        fpoint = client.get_userinfo()["fofa_point"]
        if fpoint < 100:
            break
        data = client.search(query_str, size=50, page=page,
                             fields="ip,port,domain")
        for ip, port, domain in data["results"]:
            found_domains.append({"domain": domain, "ipport": f"{ip}:{port}"})

    return found_domains


def calculate_hash(domain_name: str) -> int:
    result = run(["favscan-linux-x86_64", domain_name],
                 capture_output=True, text=True)
    return int(result.stdout)


def search_by_favicon(domains: List[str], API_key: str):
    output = {}
    for d in domains:
        hash = calculate_hash(d)
        output[d] = fofa_query(hash, API_key)

    return output
