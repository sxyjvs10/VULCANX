import requests
from bs4 import BeautifulSoup
import time

def dork_ddg(query):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    url = "https://html.duckduckgo.com/html/"
    data = {'q': query}
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        for a in soup.find_all('a', class_='result__url'):
            link = a.get('href')
            if link:
                if link.startswith('//duckduckgo.com/l/?uddg='):
                    import urllib.parse
                    link = urllib.parse.unquote(link.split('uddg=')[1].split('&')[0])
                results.append(link)
        return results
    except Exception as e:
        print(f"Error: {e}")
        return []

print(dork_ddg("site:testphp.vulnweb.com ext:php"))
