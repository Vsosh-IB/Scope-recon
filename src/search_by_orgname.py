from subprocess import run
from typing import List

import requests
from bs4 import BeautifulSoup


def viewdns_request(orgname: str) -> List[str]:
    response = requests.get(f'https://viewdns.info/reversewhois/?q={orgname}',
                            headers={
                                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 '
                                              'Firefox/130.0'})

    html = response.text
    soup = BeautifulSoup(html, "html.parser")

    table = soup.find_all('table')[2]

    entries = table.find_all('tr')

    domains = []

    for i in range(5, len(entries) - 1):
        domains.append(entries[i].find_all('td')[0].text)

    return domains


def uncover(orgname: str, file_path: str,
            # config_path: str = '/root/uncover-config.yaml',
            config_path: str = './uncover-config.yaml',
            used_modules=None):
    if used_modules is None:
        used_modules = ["shodan", "censys", "netlas"]
    result = run(['uncover', '-v', '-pc', config_path,
                  '-e', ','.join(used_modules),
                  '-o', file_path],
                 input=orgname, capture_output=True, text=True)

    print(result)
