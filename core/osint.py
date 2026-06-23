import requests
import json
from urllib.parse import urlparse

class PassiveOSINT:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.domain = urlparse(target_url).netloc
        if self.domain.startswith('www.'):
            self.domain = self.domain[4:]
            
    def fetch_alienvault_otx(self):
        print(f"[*] Querying AlienVault OTX for historical endpoints on {self.domain}...")
        urls = set()
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list"
        
        try:
            # We use a simple GET request (no API key needed for basic usage)
            resp = requests.get(otx_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if "url_list" in data:
                    for entry in data["url_list"]:
                        url = entry.get("url")
                        if url:
                            urls.add(url)
                print(f"[+] Found {len(urls)} historical URLs in AlienVault OTX!")
            else:
                print(f"[-] AlienVault OTX API returned status {resp.status_code}")
        except Exception as e:
            print(f"[-] AlienVault OTX query failed: {e}")
            
        return list(urls)

    def fetch_crtsh_subdomains(self):
        print(f"[*] Querying crt.sh for subdomains of {self.domain}...")
        subdomains = set()
        crtsh_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            resp = requests.get(crtsh_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('name_value', '').lower()
                    if name and not name.startswith('*'):
                        # Sometimes multiple names are separated by newlines
                        for part in name.split('\n'):
                            subdomains.add(part.strip())
                
                print(f"[+] Found {len(subdomains)} subdomains via Certificate Transparency (crt.sh)!")
            else:
                print(f"[-] crt.sh API returned status {resp.status_code}")
        except Exception as e:
            print(f"[-] crt.sh query failed: {e}")
            
        return list(subdomains)
