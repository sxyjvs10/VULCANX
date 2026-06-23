import os
import re
import base64
import binascii
import urllib.parse

def deobfuscate(val):
    results = []
    # Base64
    try:
        b64 = base64.b64decode(val + '=' * (-len(val) % 4)).decode('utf-8', errors='ignore')
        if any(c.isalnum() for c in b64): results.append(('Base64', b64))
    except: pass
    
    # Hex
    try:
        if len(val) >= 10 and all(c in '0123456789abcdefABCDEF' for c in val):
            h = binascii.unhexlify(val).decode('utf-8', errors='ignore')
            if any(c.isalnum() for c in h): results.append(('Hex', h))
    except: pass
    
    # Binary CSV
    try:
        if ',' in val and all(c in '01,' for c in val):
            parts = val.split(',')
            b = "".join([chr(int(p, 2)) for p in parts if p])
            if any(c.isalnum() for c in b): results.append(('Binary', b))
    except: pass

    # URL Encoding
    try:
        if '%' in val:
            u = urllib.parse.unquote(val)
            if any(c.isalnum() for c in u): results.append(('URL', u))
    except: pass
    
    return results

def main():
    root = 'crawled_data'
    keywords = ['/api/public', 'publicapi', '/public/']
    
    print(f"Searching for {keywords} in {root}...")
    
    for filename in os.listdir(root):
        path = os.path.join(root, filename)
        if not os.path.isfile(path): continue
        
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
            
            # Plain text search first
            for kw in keywords:
                if kw.lower() in content.lower():
                    print(f"[PLAIN] Found '{kw}' in {filename}")
            
            # Find all strings in quotes
            strings = re.findall(r'["\'](.*?)["\']', content)
            for s in strings:
                if len(s) < 4: continue
                deobf_results = deobfuscate(s)
                for method, decoded in deobf_results:
                    for kw in keywords:
                        if kw.lower() in decoded.lower():
                            print(f"[DEOBF] Found '{kw}' in {filename} via {method}")
                            print(f"        Original: {s[:50]}...")
                            print(f"        Decoded:  {decoded}")

if __name__ == "__main__":
    main()
