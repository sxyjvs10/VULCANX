import urllib.parse
import requests
import time
from bs4 import BeautifulSoup
import random

class GoogleDorker:
    def __init__(self, domain, api_key=None, cx=None):
        self.domain = domain
        self.api_key = api_key
        self.cx = cx
        self.dorks = {
            "Publicly Exposed Documents": f"site:{domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv",
            "Directory Listing Vulnerabilities": f"site:{domain} intitle:index.of",
            "Configuration Files": f"site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini",
            "Database Files": f"site:{domain} ext:sql | ext:dbf | ext:mdb",
            "Log Files": f"site:{domain} ext:log",
            "Backup and Old Files": f"site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
            "Login Pages": f"site:{domain} inurl:login | inurl:signin | intitle:Login",
            "SQL Errors": f"site:{domain} intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"truly a mysql result\"",
            "PHP Errors/Warnings": f"site:{domain} \"PHP Parse error\" | \"PHP Warning\" | \"PHP Error\"",
            "Wordpress": f"site:{domain} inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download",
            "Cloud Buckets": f"site:s3.amazonaws.com \"{domain}\"",
            "Subdomain Enumeration": f"site:*.{domain} | site:*.*.{domain} | site:dev.*.{domain} | site:staging.*.{domain} | site:uat.*.{domain} | site:test.*.{domain}",
            "Exposed Spreadsheets": f"site:{domain} ext:xls | ext:xlsx | ext:ods | ext:csv \"password\" | \"username\" | \"email\" | \"creds\"",
            "SSH Keys": f"site:{domain} intitle:\"index of\" id_rsa | id_dsa | authorized_keys | known_hosts | ext:pem | ext:ppk",
            "Project Management": f"site:{domain} inurl:jira | inurl:confluence | inurl:trello | inurl:slack | inurl:portal",
            "Git Folders": f"site:{domain} inurl:/.git | intitle:\"Index of /.git\"",
            "Open Redirects": f"site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http | inurl:link=",
            "Code Leaks": f"site:pastebin.com \"{domain}\" | site:jsfiddle.net \"{domain}\" | site:github.com \"{domain}\" | site:gist.github.com \"{domain}\"",
            "Sensitive Directories": f"site:{domain} inurl:/proc/self/cwd | intitle:\"index of\" \"parent directory\""
        }

    def generate_links(self):
        """
        Returns a list of tuples (Title, URL)
        """
        links = []
        for title, query in self.dorks.items():
            encoded_query = urllib.parse.quote(query)
            url = f"https://www.google.com/search?q={encoded_query}"
            links.append((title, url))
        return links

    def print_dorks(self):
        print(f"\n[*] Google Dorks for {self.domain}:")
        for title, link in self.generate_links():
            print(f"  [+] {title}:")
            print(f"      {link}")

    def execute_google_api(self):
        """
        Executes dorks using the Google Custom Search JSON API.
        """
        if not self.api_key or not self.cx:
            return None
        
        print(f"\n[*] Authenticating with Google Search API...")
        found_urls = []
        base_url = "https://www.googleapis.com/customsearch/v1"
        
        for title, query in self.dorks.items():
            params = {
                'key': self.api_key,
                'cx': self.cx,
                'q': query
            }
            try:
                response = requests.get(base_url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'items' in data:
                        print(f"  [!] {title} ({len(data['items'])} results found)")
                        for item in data['items']:
                            link = item.get('link')
                            if link:
                                print(f"      -> {link}")
                                if link not in found_urls:
                                    found_urls.append(link)
                    else:
                        print(f"  [+] {title} (0 results)")
                else:
                    print(f"  [-] Error {response.status_code} querying {title}: {response.text}")
                    if response.status_code == 403:
                         print("  [-] Quota exceeded or API Key invalid.")
                         break
            except Exception as e:
                print(f"  [-] Failed to execute API query for '{title}': {e}")
        
        return found_urls

    def execute_dorks(self):
        """
        Executes the dorks dynamically using a headless scraper (DuckDuckGo HTML).
        Returns a list of found sensitive URLs.
        """
        if self.api_key and self.cx:
            return self.execute_google_api()

        print(f"\n[*] Executing {len(self.dorks)} Dorks dynamically via stealth scraping...")
        found_urls = []
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        search_url = "https://lite.duckduckgo.com/lite/"

        for title, query in self.dorks.items():
            data = {'q': query}
            try:
                # Add random sleep to prevent rate limiting
                time.sleep(random.uniform(0.5, 1.0))
                
                response = requests.post(search_url, headers=headers, data=data, timeout=15)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Lite version uses different classes
                    results = soup.find_all('a', class_='result-url')
                    
                    if not results:
                        # Fallback for different DOM structures in Lite
                        results = soup.find_all('a', class_='result-snippet')
                        
                    if results:
                        print(f"  [!] {title} ({len(results)} results found)")
                        for a in results:
                            link = a.get('href')
                            if link:
                                # Clean up duckduckgo redirect wrappers if they exist
                                if 'uddg=' in link:
                                    link = urllib.parse.unquote(link.split('uddg=')[1].split('&')[0])
                                elif link.startswith('//'):
                                    link = "https:" + link
                                
                                if link.startswith('http'): # Ensure it's a real external link
                                    print(f"      -> {link}")
                                    if link not in found_urls:
                                        found_urls.append(link)
                    else:
                        print(f"  [+] {title} (0 results)")
                        
                elif response.status_code == 403 or response.status_code == 429:
                    print(f"  [-] Rate limit/Captcha hit (Status {response.status_code}).")
                    print("  [-] DuckDuckGo is temporarily blocking automated requests. Skipping remaining dorks.")
                    break
                elif response.status_code == 202:
                    print(f"  [-] Status 202 Accepted (Wait/Captcha needed). Skipping {title}...")
                else:
                    print(f"  [-] Error {response.status_code} querying {title}")
                
            except Exception as e:
                print(f"  [-] Failed to execute query '{title}': {e}")
        
        return found_urls
