import glob
from bbot.scanner import Scanner


def bbot_find_subdomains(OUTPUT_DIR: str, timestamp: str, domain: str) -> tuple[list[str], str]:
    scan_name = f"{OUTPUT_DIR}/subdomains_{domain.replace('.', '_')}_{timestamp}"
    scan = Scanner(domain, presets=["subdomain-enum"], output_dir=scan_name)

    for event in scan.start():
        print(event)

    try:
        subdomains_file = glob.glob(f"{scan_name}/**/subdomains.txt", recursive=True)[0]
        with open(subdomains_file, "r") as file:
            found_subdomains = file.read().split('\n')
    except Exception as e:
        print(e)
        print(f"[!] Domain {domain} unresolved, skipping")
        found_subdomains = []
        subdomains_file = ""

    return found_subdomains, subdomains_file
