import json
from urllib.parse import urlparse

class HARParser:
    def __init__(self, har_file_path):
        self.har_file_path = har_file_path
        self.entries = []
        
    def parse(self):
        print(f"[*] Parsing HAR file: {self.har_file_path}...")
        try:
            with open(self.har_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if 'log' in data and 'entries' in data['log']:
                self.entries = data['log']['entries']
                print(f"[+] Successfully loaded {len(self.entries)} network requests from HAR file.")
                return True
        except Exception as e:
            print(f"[-] Failed to parse HAR file: {e}")
        return False
        
    def extract_content(self):
        """
        Returns a dictionary of URL to Content from the HAR file.
        This mimics the output of the Crawler so it can be fed directly to the Engine.
        """
        extracted = {}
        for entry in self.entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            
            url = request.get('url', '')
            if not url:
                continue
                
            # Filter out obvious images/fonts
            if any(ext in url.lower() for ext in ['.jpg', '.png', '.gif', '.woff', '.ttf', '.css']):
                continue
                
            content = response.get('content', {})
            text = content.get('text', '')
            
            if text:
                extracted[url] = text
                
        print(f"[*] Extracted {len(extracted)} valid text/JS payloads from HAR traffic.")
        return extracted
