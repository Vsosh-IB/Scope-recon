import itertools
import subprocess
from ipaddress import IPv4Network
from typing import List, Any, Iterator
import requests
from ipwhois import IPWhois
from requests.adapters import HTTPAdapter
from urllib3 import Retry


def grouper(iterator: Iterator, n: int) -> Iterator[list]:
    while chunk := list(itertools.islice(iterator, n)):
        yield chunk


BASE_URL = 'https://REDACTED.REDACTED.REDACTED'
API_DOMAINS = '/api/REDACTED/domains?ip='
HEADERS = {
    'Authorization': 'Bearer REDACTED',
    'accept': 'application/json',
    'Content-Type': 'application/json'
}


def skipa_query(ips: List[str], blacklisted: List[str]) -> tuple[list[str], Any]:
    output_domains, output_map, processed_ips = [], [], []

    for ip in ips:
        try:
            net_name = IPWhois(ip).lookup_whois()['nets'][0]['name']
        except Exception as e:
            print(f"[!] Exception during IPWhois lookup for {ip}: {str(e)}")
            continue
        if not any(net_name.startswith(bl) for bl in blacklisted):
            processed_ips.append(ip)

    for chunk in grouper(iter(processed_ips), 100):
        full_url = f'{BASE_URL}{API_DOMAINS}{",".join(chunk)}'
        session = requests.Session()
        retries = Retry(total=3, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))

        res = session.get(full_url, headers=HEADERS, timeout=20)
        if 'items' in res.json() and res.json()['items']:
            domains = [d.lower() for d in res.json()['items'][0].get('domains', [])]
            output_domains.extend(domains)
            output_map.extend(res.json()['items'])

    return output_domains, output_map


def rdns_lookup(ip: str) -> List[str]:
    try:
        prips_result = subprocess.Popen(('prips', ip), stdout=subprocess.PIPE)
        prips_result.wait()
        result = subprocess.run(("hakrevdns", '-r', '1.1.1.1', '-t', '30', '-d'), stdin=prips_result.stdout,
                                capture_output=True, text=True)
        if result.returncode == 0:
            return list(set(result.stdout.strip().splitlines()))
        else:
            print(f"Error running hakrevdns with 1.1.1.1 on {ip}: {result.stderr}")
    except Exception as e:
        print(f"Exception during rDNS lookup for {ip}: {str(e)}")
    return []


def rdns(ips: List[str], blacklisted: List[str]) -> tuple[list[str], dict[str, list[str]]]:
    return_domains, map_domains = [], {}

    for ip in ips:
        net_name = IPWhois(ip).lookup_whois()['nets'][0]['name']

        if any(net_name.startswith(bl) for bl in blacklisted):
            continue

        domains_for_ip = rdns_lookup(ip)
        map_domains[ip] = domains_for_ip
        return_domains.extend(domains_for_ip)

    print(f"[+] Получено {len(return_domains)} rDNS записей:")
    return return_domains, map_domains
