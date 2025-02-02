import argparse
import glob
import json
import os
from datetime import datetime
from typing import List

from misc.search_by_favicon import search_by_favicon
from rdns import rdns, skipa_query
from resolve import get_whois, resolve_all, resolve_list
from search_by_orgname import viewdns_request, uncover
from subdomains_finder import bbot_find_subdomains

OUTPUT_DIR = "/mnt/"
timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)


def filter_blacklist(domains: List[str], blacklist: List[str]) -> List[str]:
    return [domain for domain in domains if domain not in blacklist]


def parse_args():
    parser = argparse.ArgumentParser(description="All-in-one scope recon tool")
    parser.add_argument('-n', '--projname', required=True, type=str,
                        help="Название проекта, в папке которого будут все результаты")
    parser.add_argument('-i', '--ips', type=str, help="Путь до файла с IP адресами")
    parser.add_argument('-d', '--domains', type=str, help="Путь до файла со списком доменов")
    parser.add_argument('-o', '--orgnames', type=str, help="Путь до файла со списком названий организации")
    parser.add_argument('-b', '--blacklist', type=str, default=None, help="Путь до файла с blacklist'ом")
    parser.add_argument('-f', '--favicons', type=str, default=None,
                        help="Путь до файла с доменами для поиска по фавайконам")
    return parser.parse_args()


def read_file(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File {file_path} not found.")
        return []


def bbot_output(output_dir: str) -> dict[str, set[str]]:
    out = {}
    with open(glob.glob(f"{output_dir}/**/output.json", recursive=True)[0], "r") as file:
        for line in file:
            entry = json.loads(line)
            if entry.get("type") == "DNS_NAME" and entry.get("scope_description") == "in-scope":
                out[entry.get("data")] = entry.get("module")
    return out


def bbot_get_asns(output_dir: str) -> dict[str, dict[str, str]]:
    out = {}
    with open(glob.glob(f"{output_dir}/**/output.json", recursive=True)[0], "r") as file:
        for line in file:
            entry = json.loads(line)
            if entry.get("type") == "ASN":
                out[entry.get("data").get("asn")] = {
                    "name": entry.get("data").get("name"),
                    "description": entry.get("data").get("description"),
                    "subnet": entry.get("data").get("subnet")
                }
    return out


output = {}
blacklisted_companies = ["AKAMAI", "QRATOR", "TildaPublishing"]


def main():
    global OUTPUT_DIR
    args = parse_args()
    OUTPUT_DIR += args.projname

    found_subdomains = []
    blacklist = read_file(args.blacklist) if args.blacklist else []
    print(OUTPUT_DIR)

    if args.orgnames:
        print(f"[+] Получен файл {args.orgnames} со списком IP-адресов")
        target_names = read_file(args.orgnames)
        print(f"[+] Длина списка названий: {len(target_names)}")

        found_domains, found_ips = [], []

        os.makedirs(f"{OUTPUT_DIR}/uncover/", exist_ok=True)
        for name in target_names:
            found_domains += viewdns_request(name)
            filename = f"{OUTPUT_DIR}/uncover/{name}"
            uncover(name, filename)
            found_ips += read_file(filename)

        print(f"[+] Все запросы обработаны")

        found_ips = list(filter(None, set(found_ips)))
        only_ips = [ip.rsplit(':')[0] for ip in found_ips]
        skipa_rdns_ips = skipa_query(only_ips, blacklisted_companies)

        output.update({
            "rev_whois": found_domains,
            "asm_ips": found_ips,
            "asm_skipa_rdns": skipa_rdns_ips
        })

    if args.ips and args.domains:
        print(f"[+] Получен файл {args.ips} со списком IP-адресов")
        print(f"[+] Получен файл {args.domains} со списком доменов")
        target_domains = read_file(args.domains)
        target_ips = read_file(args.ips)
        print(f"[+] Длина списка IP-адресов: {len(target_ips)}")
        print(f"[+] Длина списка доменов: {len(target_domains)}")

        found_subdomains += target_domains

        bbot_subdomains, bbot_subdomains_paths, bbot_out, bbot_asns = [], [], {}, {}
        for domain in target_domains:
            print(f"[+] Начат поиск поддоментов для домена: {domain}")
            bbot_subdomain, bbot_path = bbot_find_subdomains(OUTPUT_DIR, timestamp, domain)
            bbot_subdomains += bbot_subdomain
            bbot_subdomains_paths += bbot_path
            print(f"[+] Получено {len(bbot_subdomain)} поддоменов")

            bbot_out[domain] = bbot_output(bbot_path[0: bbot_path.rfind('/')])
            bbot_asns[domain] = bbot_get_asns(bbot_path[0: bbot_path.rfind('/')])

        bbot_subdomains = filter_blacklist(bbot_subdomains, blacklist)
        output.update({
            "bbot_subdomains": bbot_subdomains[:-1],
            "bbot_info": bbot_out,
            "bbot_asns": bbot_asns
        })
        found_subdomains += bbot_subdomains

        print(f"[+] Начат резолв доменов и поддоменов")
        ip_set = set(target_ips)
        matched_records, unmatched_records, all_resolved = [], [], []
        for domains_chunk_path in bbot_subdomains_paths:
            resolved = resolve_all(OUTPUT_DIR, timestamp, domains_chunk_path)
            all_resolved += resolved
            for record in resolved:
                record_ip = record.split()[-1]
                if record_ip in ip_set:
                    matched_records.append(record)
                else:
                    unmatched_records.append(get_whois(record_ip))

        print(f"[+] Получено {len(matched_records)} в скоупе и {len(unmatched_records)} вне скоупа")
        output.update({
            "fqdns_in_scope": matched_records,
            "whois": unmatched_records
        })

    else:
        if args.ips:
            print(f"[+] Получен файл {args.ips} со списком IP-адресов")
            target_ips = read_file(args.ips)
            print(f"[+] Длина списка IP: {len(target_ips)}")

            rdns_domains, map_ip_to_domains_rdns = rdns(target_ips, blacklisted_companies)
            found_subdomains += rdns_domains
            print(f"[+] Обработаны все rDNS запросы")
            skipa_domains, map_ip_to_domains_skipa = skipa_query(target_ips, blacklisted_companies)
            found_subdomains += skipa_domains
            print(f"[+] Обработаны все rDNS запросы к СКИПА")

            output.update({
                "rdns": map_ip_to_domains_rdns,
                "skipa_rdns": map_ip_to_domains_skipa
            })

        if args.domains:
            print(f"[+] Получен файл {args.ips} со списком IP-адресов")
            target_domains = read_file(args.domains)
            found_subdomains += target_domains
            print(f"[+] Длина списка доменов: {len(target_domains)}")

            bbot_subdomains, bbot_subdomains_paths, bbot_out, bbot_asns = [], [], {}, {}
            for domain in target_domains:
                print(f"[+] Начат поиск поддоментов для домена: {domain}")
                bbot_subdomain, bbot_path = bbot_find_subdomains(OUTPUT_DIR, timestamp, domain)
                bbot_subdomains += bbot_subdomain
                bbot_subdomains_paths += bbot_path
                bbot_out[domain] = bbot_output(bbot_path[0: bbot_path.rfind('/')])
                bbot_asns[domain] = bbot_get_asns(bbot_path[0: bbot_path.rfind('/')])
                print(f"[+] Получено {len(bbot_subdomain)} поддоменов")

            bbot_subdomains = filter_blacklist(bbot_subdomains, blacklist)
            resolved = resolve_list(bbot_subdomains, OUTPUT_DIR, timestamp)
            resolved_subdomains = {rec.split()[0]: rec.split()[-1] for rec in resolved}

            output.update({
                "resolved_subdomains": resolved_subdomains,
                "bbot_subdomains": bbot_subdomains[:-1],
                "bbot_info": bbot_out,
                "bbot_asns": bbot_asns
            })
            found_subdomains += bbot_subdomains

    if args.favicons:
        target_domains = read_file(args.favicons)
        with open("fofa_key.txt") as f:
            fofa_key = f.read().split('\n')[0]
        output["favicon_search"] = search_by_favicon(target_domains, fofa_key)

    print(f"[+] Начата запись вывода")
    with open(f"{OUTPUT_DIR}/output_{timestamp}.json", "w") as f:
        f.write(json.dumps(output, indent=4, cls=SetEncoder))
    print(f"[+] Выполнение завершено успешно")


if __name__ == '__main__':
    main()
