import requests
import json
from urllib.parse import urlparse

class WaybackMachineRecon:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.domain = urlparse(target_url).netloc
        if self.domain.startswith('www.'):
            self.domain = self.domain[4:]
            
    def fetch_historical_urls(self):
        print(f"[*] Querying Wayback Machine for historical endpoints on {self.domain}...")
        
        # cdx API endpoint
        # fl=original: We only need the original URL
        # filter=mimetype:text/html: We mostly care about pages/api endpoints, but let's grab everything and filter locally
        # collapse=urlkey: remove duplicates
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&collapse=urlkey&output=json&fl=original,mimetype"
        
        try:
            resp = requests.get(cdx_url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if not data or len(data) <= 1:
                    print("[-] No historical URLs found in Wayback Machine.")
                    return []
                
                # The first row is the header: ["original", "mimetype"]
                urls = set()
                # Interesting extensions we want to highlight or test
                interesting_exts = ('.json', '.xml', '.php', '.asp', '.aspx', '.jsp', '.txt', '.env', '.bak', '.sql')
                
                for row in data[1:]:
                    if len(row) >= 2:
                        original_url = row[0]
                        mimetype = row[1]
                        
                        # Filter out junk
                        if mimetype in ['image/jpeg', 'image/png', 'image/gif', 'text/css', 'font/woff', 'font/woff2']:
                            continue
                            
                        # If it has parameters or is an interesting file type, save it
                        if '?' in original_url or original_url.endswith(interesting_exts) or 'api/' in original_url.lower():
                            urls.add(original_url)
                            
                print(f"[+] Found {len(urls)} potentially interesting historical endpoints!")
                return list(urls)
            else:
                print(f"[-] Wayback Machine API returned status {resp.status_code}")
                return []
        except Exception as e:
            print(f"[-] Wayback Machine query failed: {e}")
            return []
