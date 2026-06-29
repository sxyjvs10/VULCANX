import os
import sys
import requests
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.vdb import VulnerabilityDB

# A curated list of keywords for common web components
COMPONENTS = [
    "jquery", "bootstrap", "angularjs", "vue", "react", "lodash", "moment",
    "wordpress", "apache", "nginx", "php", "express"
]

# We include a small seed of well-known CVEs to ensure the tool has data 
# immediately, even if the NVD API rate limits us or fails.
SEED_DATA = [
    ("CVE-2020-11022", "jquery", "<3.5.0", "MEDIUM", "In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code.", "2020-04-29"),
    ("CVE-2019-11358", "jquery", "<3.4.0", "MEDIUM", "jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution", "2019-04-20"),
    ("CVE-2015-9251", "jquery", "<3.0.0", "MEDIUM", "jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.", "2018-01-18"),
    ("CVE-2021-21315", "express", "all", "HIGH", "Systeminformation is an open source Node.js application. In systeminformation before version 5.3.1 there is a command injection vulnerability.", "2021-02-15"), # Just an example
    ("CVE-2019-8331", "bootstrap", "<4.3.1", "MEDIUM", "In Bootstrap before 3.4.1 and 4.3.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.", "2019-02-20"),
    ("CVE-2018-14041", "bootstrap", "<4.1.2", "MEDIUM", "In Bootstrap before 4.1.2, XSS is possible in the data-target property of scrollspy.", "2018-07-13"),
    ("CVE-2021-41184", "jquery", "<3.0.0", "MEDIUM", "jQuery UI before 1.13.0 is vulnerable to XSS.", "2021-10-26")
]

def fetch_from_nvd(keyword):
    # This is a simplified fetching mechanism using the NVD 2.0 API.
    # Note: Without an API key, rate limits are strict (5 requests / 30 seconds).
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
    print(f"[*] Fetching CVEs for {keyword} from NVD...")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        elif response.status_code == 403:
            print("[-] Rate limited by NVD. Sleeping for 10 seconds...")
            time.sleep(10)
            return fetch_from_nvd(keyword)
        else:
            print(f"[-] Failed to fetch data for {keyword} (Status: {response.status_code})")
            return []
    except Exception as e:
        print(f"[-] Error fetching {keyword}: {e}")
        return []

def main():
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'vuln_data.db'))
    print(f"[*] Starting Vulnerability DB Updater...")
    vdb = VulnerabilityDB(db_path=db_path)
    
    total_added = 0
    
    print("[*] Seeding local DB with known critical CVEs...")
    for cve in SEED_DATA:
        vdb.add_vulnerability(cve[0], cve[1], cve[2], cve[3], cve[4], cve[5])
        total_added += 1
    
    print("[*] Contacting National Vulnerability Database (NVD) for updates...")
    for comp in COMPONENTS:
        vulns = fetch_from_nvd(comp)
        added_for_comp = 0
        for item in vulns:
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id: continue
            
            # Extract description
            desc = "No description"
            for description in cve.get('descriptions', []):
                if description.get('lang') == 'en':
                    desc = description.get('value')
                    break
            
            # Extract severity
            severity = "UNKNOWN"
            metrics = cve.get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
            if cvss_data:
                severity = cvss_data[0].get('cvssData', {}).get('baseSeverity', 'UNKNOWN').upper()
            elif metrics.get('cvssMetricV2'):
                severity = metrics.get('cvssMetricV2')[0].get('baseSeverity', 'UNKNOWN').upper()
            
            published_date = cve.get('published', '')
            
            # Extract version affected
            version_affected = "UNKNOWN"
            configurations = cve.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable'):
                            cpe23Uri = match.get('criteria') 
                            versionEndIncluding = match.get('versionEndIncluding')
                            versionEndExcluding = match.get('versionEndExcluding')
                            
                            if versionEndIncluding:
                                version_affected = f"<={versionEndIncluding}"
                            elif versionEndExcluding:
                                version_affected = f"<{versionEndExcluding}"
                            elif cpe23Uri:
                                parts = cpe23Uri.split(':')
                                if len(parts) > 5 and parts[5] != '*':
                                    version_affected = parts[5]
                            
                            if version_affected != "UNKNOWN":
                                break
                    if version_affected != "UNKNOWN":
                        break
                if version_affected != "UNKNOWN":
                    break

            # Add to local db
            vdb.add_vulnerability(cve_id, comp.lower().replace("_", " "), version_affected, severity, desc, published_date)
            added_for_comp += 1
            
        print(f"[+] Added {added_for_comp} vulnerabilities for {comp}.")
        total_added += added_for_comp
        
        # Respect NVD API rate limits (5 req/30 sec without key = ~6s per req)
        time.sleep(6.5)
        
    vdb.set_last_update()
    print(f"\n[*] Update complete! Added {total_added} vulnerabilities to the local DB.")
    print(f"[*] The Passive Software Component Scanner is now armed with current CVE data.")

if __name__ == "__main__":
    main()
