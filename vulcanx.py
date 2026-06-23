#!/usr/bin/env python3
import argparse
import sys
import os
import hashlib
import time
import re
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path to allow importing modules from root
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.behavior import SessionManager
from core.mapper import Crawler
from core.engine import Analyzer
from core.report import Reporter
from utils.login_manager import LoginManager
from core.vdb import VulnerabilityDB
from core.pool import WebDriverPool
from utils.nvd_updater import NVDUpdater
from core.dorker import GoogleDorker
from core.discovery import PathEnumerator
from core.har_parser import HARParser
from core.live_browser import LiveBrowserInterceptor

def main():
    parser = argparse.ArgumentParser(description="VulcanX - Advanced Web Application Source Code Scanner (Client-Side)")
    parser.add_argument("-u", "--url", required=False, help="Target URL (e.g., https://example.com/dashboard)")
    parser.add_argument("-c", "--cookies", help="Session Cookies (e.g., 'sessionid=xyz; auth=abc')")
    parser.add_argument("-H", "--headers", action="append", help="Custom Headers (e.g., 'Authorization: Bearer token')")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Crawling Depth (default: 3)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file (JSON/HTML)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL Verification")
    parser.add_argument("-b", "--browser", action="store_true", help="Use Headless Browser (Selenium) for crawling")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output for all findings")
    parser.add_argument("--save-content", action="store_true", help="Save all crawled content to local files")
    parser.add_argument("--min-severity", choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW', help="Minimum severity to report (default: LOW)")
    parser.add_argument("--ignore-list", help="Path to a text file containing strings/regexes to ignore (False Positives)")
    parser.add_argument("--update-db", action="store_true", help="Update the local vulnerability database from NVD")
    parser.add_argument("--har", help="Path to a HAR file to ingest and scan (Bypasses active crawling)")
    parser.add_argument("-m", "--manual-browse", action="store_true", help="Launch a live browser for manual interaction and dynamically scan all intercepted traffic.")
    
    # Auto-Login Arguments
    parser.add_argument("--login-url", help="Login Page URL for Auto-Login")
    parser.add_argument("--username", help="Username for Auto-Login")
    parser.add_argument("--password", help="Password for Auto-Login")
    
    # New Strategies
    parser.add_argument("--live-exploit", action="store_true", help="Inject AES Interceptor and monitor for keys (Requires -b)")
    parser.add_argument("--scan-all", action="store_true", help="Run ALL strategies (Static, Dynamic) to find keys.")
    parser.add_argument("--key-and-file-scan-only", action="store_true", help="Run only key pattern detection and sensitive file disclosure scans.")
    
    # Discovery Features
    parser.add_argument("--dorks", action="store_true", help="Generate and display Google Dorks, and dynamically execute them without API keys")
    parser.add_argument("--hidden-scan", action="store_true", help="Perform a directory brute-force scan to find hidden files/folders")
    parser.add_argument("--wordlist", help="Custom wordlist file for --hidden-scan (optional)")
    
    # Authenticated Dorking
    parser.add_argument("--google-api-key", help="Google Custom Search API Key")
    parser.add_argument("--google-cx", help="Google Custom Search Engine ID (CX)")

    args = parser.parse_args()

    if not args.url and not args.har:
        print("[-] Error: You must provide either a Target URL (-u) or a HAR file (--har).")
        sys.exit(1)

    # Load from config.json if it exists
    config = {}
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"[-] Failed to load config.json: {e}")

    # Prioritize CLI args over config file
    google_api_key = args.google_api_key or config.get("google_api_key")
    google_cx = args.google_cx or config.get("google_cx")

    # Initialize DB & Cookies (Used by both normal and scan-all modes)
    print("[*] Initializing VULCANX...")
    vuln_db = VulnerabilityDB()
    final_cookies = args.cookies

    # Live Browser Mode Execution
    if args.manual_browse:
        if not args.url:
            print("[-] Error: You must provide a Target URL (-u) to start the Live Browser.")
            sys.exit(1)
            
        analyzer = Analyzer(vuln_db=vuln_db)
        interceptor = LiveBrowserInterceptor(analyzer)
        interceptor.start(args.url)
        sys.exit(0)

    # --- Discovery & Reconnaissance Features ---
    if args.dorks:
        try:
            from urllib.parse import urlparse
            domain = urlparse(args.url).netloc
            dorker = GoogleDorker(domain, api_key=google_api_key, cx=google_cx)
            print(f"[*] Dynamically executing Dorks for {domain}...")
            found_urls = dorker.execute_dorks()
            if found_urls:
                print(f"\n[+] Dynamic Dorking Complete. Found {len(found_urls)} sensitive links:")
                for url in found_urls:
                    print(f"    -> {url}")
            else:
                print("\n[-] Dynamic Dorking Complete. No sensitive links found.")
            print("-" * 60)
        except Exception as e:
            print(f"[-] Dork generation failed: {e}")

    if args.hidden_scan:
        print("[*] Starting Hidden Directory Scan...")
        # Load wordlist if provided
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Failed to load wordlist: {e}")
                sys.exit(1)
        
        enumerator = PathEnumerator(args.url, wordlist=wordlist, threads=args.threads)
        found_paths = enumerator.start()
        print(f"[+] Hidden Scan Complete. Found {len(found_paths)} paths.")
        for p in found_paths:
             print(f"    - {p['url']} (Status: {p['status']}, Size: {p['size']})")
        print("-" * 60)
    # -------------------------------------------

    # Helper to get payload path
    payload_path = os.path.join(os.path.dirname(__file__), "payloads", "aes_live.js")

    # Handle Scan All Mode
    if args.key_and_file_scan_only:
        print("[*] STARTING FOCUSED KEY AND SENSITIVE FILE SCAN...")
        print("="*60)
        
        all_findings = []

        # 1. Sensitive File Disclosure (Dorks)
        print("\n[PHASE 0] Sensitive File Disclosure (Google Dorks)...")
        try:
            from urllib.parse import urlparse
            domain = urlparse(args.url).netloc
            dorker = GoogleDorker(domain, api_key=google_api_key, cx=google_cx)
            print(f"[*] Dynamically executing Dorks for {domain}...")
            found_urls = dorker.execute_dorks()
            if found_urls:
                print(f"\n[+] Dynamic Dorking Complete. Found {len(found_urls)} sensitive links:")
                for url in found_urls:
                    all_findings.append({
                        'url': url,
                        'type': 'SENSITIVE_FILE_DISCLOSURE_DORK',
                        'severity': 'MEDIUM',
                        'description': 'Potential sensitive file or information exposed via Google Dorks.',
                        'remediation': 'Review the content at this URL for sensitive data. Restrict access or remove exposed files.',
                        'match': url,
                        'context': 'Discovered via Google Dorking.',
                        'line': 0,
                        'source': 'DORK'
                    })
                    print(f"    -> {url}")
            else:
                print("\n[-] Dynamic Dorking Complete. No sensitive links found.")
        except Exception as e:
            print(f"[-] Dork execution failed: {e}")

        # 2. Sensitive File Disclosure (Hidden Files/Folders)
        print("\n[*] Starting Targeted Sensitive File Scan...")
        try:
            target_wordlist = None
            wordlist_path = args.wordlist if args.wordlist else 'sensitive_files_wordlist.txt'
            try:
                if os.path.exists(wordlist_path):
                    with open(wordlist_path, 'r') as f:
                        target_wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Failed to load wordlist {wordlist_path}: {e}")

            enumerator = PathEnumerator(args.url, wordlist=target_wordlist, threads=args.threads)
            found_paths = enumerator.start()
            print(f"[+] Hidden Scan Complete. Found {len(found_paths)} paths.")
            
            # Fetch and analyze content of found paths
            print("[*] Analyzing content of discovered sensitive files...")
            for p in found_paths:
                if p['status'] == 200:
                    try:
                        resp = session_manager.get(p['url'])
                        if resp.status_code == 200:
                            content = resp.text
                            # Analyze this content for keys
                            from utils.decryption.strategies.generic_key_pattern_strategy import GenericKeyPatternStrategy
                            key_strategy = GenericKeyPatternStrategy()
                            findings = key_strategy.detect_and_decrypt(content, p['url'])
                            if findings:
                                all_findings.extend(findings)
                                print(f"    [!] Found {len(findings)} key(s) in {p['url']}")
                            
                            # Also add it to all_findings as a file disclosure
                            all_findings.append({
                                'url': p['url'],
                                'type': 'SENSITIVE_FILE_DISCLOSURE_BRUTEFORCE',
                                'severity': 'MEDIUM',
                                'description': f'Potential sensitive file found via brute-force (Status: 200, Size: {p["size"]}).',
                                'remediation': 'Restrict access to this path or remove exposed file.',
                                'match': p['url'],
                                'context': f'Size: {p["size"]}',
                                'line': 0,
                                'source': 'HIDDEN_SCAN'
                            })
                    except Exception as e:
                        print(f"    [-] Failed to fetch content for {p['url']}: {e}")
                else:
                    # Non-200 but interesting status
                    all_findings.append({
                        'url': p['url'],
                        'type': 'SENSITIVE_FILE_DISCLOSURE_BRUTEFORCE',
                        'severity': 'LOW',
                        'description': f'Interesting status code found via brute-force (Status: {p["status"]}, Size: {p["size"]}).',
                        'remediation': 'Investigate the access permissions for this path.',
                        'match': p['url'],
                        'context': f'Status: {p["status"]}, Size: {p["size"]}',
                        'line': 0,
                        'source': 'HIDDEN_SCAN'
                    })
        except Exception as e:
            print(f"[-] Hidden scan failed: {e}")

        # 3. Key Pattern Detection
        print("\n[PHASE 1] Key Pattern Detection...")
        session_manager = SessionManager(cookies=final_cookies, headers=args.headers, ssl_verify=not args.insecure, use_browser=False)
        try:
            crawler = Crawler(session_manager, args.url, depth=0, max_workers=1) # Only crawl the target URL itself
            crawled_pages, _ = crawler.start()

            analyzer = Analyzer(vuln_db=vuln_db)
            key_findings = []
            for url, content in crawled_pages.items():
                from utils.decryption.strategies.generic_key_pattern_strategy import GenericKeyPatternStrategy
                key_strategy = GenericKeyPatternStrategy()
                key_findings.extend(key_strategy.detect_and_decrypt(content, url))
            
            all_findings.extend(key_findings)
            print(f"[+] Found {len(key_findings)} potential key patterns.")

        except Exception as e:
            print(f"[-] Key Pattern Detection Failed: {e}")
        finally:
            if session_manager:
                session_manager.close()

        # Filter Findings by Severity
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        min_score = severity_map.get(args.min_severity, 0)
        
        filtered_findings = [
            f for f in all_findings 
            if severity_map.get(f.get('severity', 'INFO'), 0) >= min_score
        ]

        # Final Report
        print("\n" + "="*60)
        print("FOCUSED SCAN COMPLETE")
        print(f"Total Findings: {len(filtered_findings)}")
        
        print("\n[*] Generating Report...")
        reporter = Reporter(filtered_findings, verbose=args.verbose)
        reporter.print_summary()

        # Save Report if requested
        if args.output:
            reporter.save(args.output)
        
        sys.exit(0)
    
    if args.scan_all:
        print("[*] STARTING COMPREHENSIVE SCAN (ALL STRATEGIES)...")
        print("="*60)
        
        findings_summary = {
            "static": 0,
            "dynamic": 0,
            "keys_found": []
        }
        discovery_findings = []

        # 0. Discovery & Reconnaissance (New)
        print("\n[PHASE 0] Discovery & Reconnaissance...")
        try:
            from urllib.parse import urlparse
            domain = urlparse(args.url).netloc
            dorker = GoogleDorker(domain, api_key=google_api_key, cx=google_cx)
            print(f"[*] Dynamically executing Dorks for {domain}...")
            found_urls = dorker.execute_dorks()
            if found_urls:
                print(f"\n[+] Dynamic Dorking Complete. Found {len(found_urls)} sensitive links:")
                for url in found_urls:
                    discovery_findings.append({
                        'url': url,
                        'type': 'SENSITIVE_FILE_DISCLOSURE_DORK',
                        'severity': 'MEDIUM',
                        'description': 'Potential sensitive file or information exposed via Google Dorks.',
                        'remediation': 'Review the content at this URL for sensitive data. Restrict access or remove exposed files.',
                        'match': url,
                        'context': 'Discovered via Google Dorking.',
                        'line': 0,
                        'source': 'DORK'
                    })
                    print(f"    -> {url}")
        except Exception as e:
            print(f"[-] Dork execution failed: {e}")

        print("\n[*] Starting Targeted Sensitive File Scan...")
        try:
            target_wordlist = None
            wordlist_path = args.wordlist if args.wordlist else 'sensitive_files_wordlist.txt'
            try:
                if os.path.exists(wordlist_path):
                    with open(wordlist_path, 'r') as f:
                        target_wordlist = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Failed to load wordlist {wordlist_path}: {e}")

            enumerator = PathEnumerator(args.url, wordlist=target_wordlist, threads=args.threads)
            found_paths = enumerator.start()
            print(f"[+] Hidden Scan Complete. Found {len(found_paths)} paths.")
            # We don't print all 100+ paths here to avoid cluttering the summary view, 
            # but we could save them or print a sample.
            for p in found_paths[:5]:
                 print(f"    - {p['url']} (Status: {p['status']}, Size: {p['size']})")
            if len(found_paths) > 5:
                print(f"    ... and {len(found_paths)-5} more.")
                
            for p in found_paths:
                if p['status'] == 200:
                    discovery_findings.append({
                        'url': p['url'],
                        'type': 'SENSITIVE_FILE_DISCLOSURE_BRUTEFORCE',
                        'severity': 'MEDIUM',
                        'description': f'Potential sensitive file found via brute-force (Status: 200, Size: {p["size"]}).',
                        'remediation': 'Restrict access to this path or remove exposed file.',
                        'match': p['url'],
                        'context': f'Size: {p["size"]}',
                        'line': 0,
                        'source': 'HIDDEN_SCAN'
                    })
                else:
                    discovery_findings.append({
                        'url': p['url'],
                        'type': 'SENSITIVE_FILE_DISCLOSURE_BRUTEFORCE',
                        'severity': 'LOW',
                        'description': f'Interesting status code found via brute-force (Status: {p["status"]}, Size: {p["size"]}).',
                        'remediation': 'Investigate the access permissions for this path.',
                        'match': p['url'],
                        'context': f'Status: {p["status"]}, Size: {p["size"]}',
                        'line': 0,
                        'source': 'HIDDEN_SCAN'
                    })
        except Exception as e:
            print(f"[-] Hidden scan failed: {e}")

        # 1. Static Scan (with Browser for Network Logs)
        print("\n[PHASE 1] Static & Network Analysis (Crawling, Source Code & API Scan)...")
        analyzer = Analyzer(vuln_db=vuln_db) # Initialize analyzer here
        
        crawled_pages = {}
        network_urls = set()
        header_findings = []
        session_manager_static = None

        if args.har:
            print(f"[*] INGESTING HAR FILE: {args.har} (Bypassing active crawler)")
            har_parser = HARParser(args.har)
            if har_parser.parse():
                crawled_pages = har_parser.extract_content()
                network_urls = set(crawled_pages.keys())
            else:
                print("[-] Aborting due to HAR parsing failure.")
                sys.exit(1)
        else:
            # Ensure browser is ON for comprehensive crawl to capture network logs and execute JS
            session_manager_static = SessionManager(cookies=final_cookies, headers=args.headers, ssl_verify=not args.insecure, use_browser=True)
            try:
                crawler = Crawler(session_manager_static, args.url, depth=args.depth, max_workers=args.threads)
                crawled_pages, network_urls, header_findings = crawler.start()

                # Add header findings to discovery findings
                if header_findings:
                    print(f"[+] Found {len(header_findings)} missing security header issues.")
                    discovery_findings.extend(header_findings)

                # Capture and analyze network logs
                print("[*] Analyzing network logs for API responses...")
                network_responses = session_manager_static.get_network_logs()
                
                # This is where we'll store network findings
                network_findings = []

                for url, content in network_responses.items():
                    is_json = False
                    try:
                        json_data = json.loads(content)
                        is_json = True
                        print(f"[+] JSON API Response from {url}:")
                        print(f"    Content (last 200 chars): {content[-200:]}")
                        # Look for "rotating key" pattern in the *content*
                        # A simple regex to detect patterns like "key": "some_long_base64_or_hex_string" at the end of the JSON
                        if re.search(r'(?:"key"|"token"|"secret")\s*:\s*"[a-zA-Z0-9+/=]{16,}$', content[-200:], re.IGNORECASE):
                            finding = {
                                "url": url,
                                "type": "POTENTIAL_ROTATING_KEY",
                                "severity": "HIGH",
                                "description": "Potential rotating key pattern found in API response.",
                                "remediation": "Investigate the API response for dynamic key generation or sensitive data. Ensure proper key management.",
                                "match": content[-200:],
                                "context": f"Full response (last 500 chars): {content[-500:]}",
                                "line": 0,
                                "source": "NETWORK"
                            }
                            network_findings.append(finding)
                            print(f"    [!!!] Potential rotating key pattern found in last 200 characters of response from {url}")
                    except json.JSONDecodeError:
                        pass # Not valid JSON, process as plain text/JS

                    if not is_json:
                        print(f"[+] Text/JS Response from {url}:\n    Content (last 200 chars): {content[-200:]}")

            except Exception as e:
                print(f"[-] Static Crawl Failed: {e}")
            finally:
                 # Important to close the first browser instance before starting the dynamic one
                 if session_manager_static:
                     session_manager_static.close()

        # Execute static scan on the gathered pages (either from HAR or Crawler)
        try:
            static_findings = analyzer.scan(crawled_pages, network_urls)
            findings_summary["static"] = len(static_findings)
            for f in static_findings:
                if f['severity'] in ['CRITICAL', 'HIGH']:
                    # Use decoded value if available (for decrypted secrets), otherwise use the match
                    if f.get('decoded_value'):
                        val = f.get('decoded_value')
                    else:
                        val = f.get('match')
                        
                    # Clean up context for display if needed
                    if "SUSPICIOUS_FUNC_ARG_KEY" in f['type']:
                         # Extract just the key string if possible
                         m = re.search(r'["\']([a-zA-Z0-9]{16,32})["\']', val)
                         if m: val = m.group(1)
                    
                    findings_summary["keys_found"].append(f"[Static] {f['type']}: {val}")
        except Exception as e:
             print(f"[-] Static Scan Failed: {e}")

        # 2. Dynamic Scan
        print("\n[PHASE 2] Dynamic Analysis (Browser Interception)...")
        session_manager_dynamic = SessionManager(
            cookies=final_cookies, 
            headers=args.headers, 
            ssl_verify=not args.insecure, 
            use_browser=True, 
            live_exploit_script=payload_path
        )
        try:
            # Just visit the main URL and wait for interception
            print(f"[*] Visiting {args.url} with AES Interceptor (Waiting 15s)...")
            session_manager_dynamic.get(args.url)
            
            # Force load unlinked JS assets into the current page context
            unlinked_js = [u for u in crawled_pages.keys() if u.endswith('.js') and u != args.url]
            if unlinked_js:
                print(f"[*] Sideloading {len(unlinked_js)} unlinked scripts into browser context...")
                for js_url in unlinked_js:
                    session_manager_dynamic.driver.execute_script(f"""
                        var s = document.createElement('script');
                        s.src = '{js_url}';
                        document.head.appendChild(s);
                    """)

            # Give it time to run scripts
            time.sleep(30) 
            # Force read one last time just in case
            session_manager_dynamic.read_console_logs()
            
            logs = session_manager_dynamic.captured_logs
            findings_summary["dynamic"] = len(logs)
            for log in logs:
                if any(indicator in log for indicator in ["KEY", "FOUND GLOBAL", "🔓", "🔥", "Auto-Decrypted"]):
                    findings_summary["keys_found"].append(f"[Dynamic] {log}")
        except Exception as e:
            print(f"[-] Dynamic Scan Failed: {e}")
        finally:
            session_manager_dynamic.close()

        # Consolidate Findings for Report
        all_findings = []
        if 'discovery_findings' in locals():
            all_findings.extend(discovery_findings)
        if 'static_findings' in locals():
            all_findings.extend(static_findings)
        
        # Convert dynamic logs to findings objects
        if 'logs' in locals():
            for log in logs:
                all_findings.append({
                    'url': args.url,
                    'type': 'DYNAMIC_INTERCEPTION',
                    'severity': 'HIGH' if any(x in log for x in ["KEY", "IV", "Decrypted"]) else 'INFO',
                    'description': 'Dynamic interception of cryptographic operation or secret.',
                    'remediation': 'Review the intercepted data context.',
                    'match': log[:100] + "...",
                    'context': log,
                    'line': 0,
                    'source': 'DYNAMIC'
                })
        
        # Filter Findings by Severity
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        min_score = severity_map.get(args.min_severity, 0)
        
        filtered_findings = [
            f for f in all_findings 
            if severity_map.get(f.get('severity', 'INFO'), 0) >= min_score
        ]

        # Final Report
        print("\n" + "="*60)
        print("COMPREHENSIVE SCAN COMPLETE")
        print(f"Static Findings: {findings_summary['static']}")
        print(f"Dynamic Interceptions: {findings_summary['dynamic']}")
        
        print("\n[*] Generating Comprehensive Report...")
        reporter = Reporter(filtered_findings, verbose=args.verbose)
        reporter.print_summary()

        # Save Report if requested
        if args.output:
            reporter.save(args.output)
        
        sys.exit(0)

    if args.live_exploit:
        args.browser = True # Force browser mode
        print("[*] Live Exploit Mode Enabled: Injecting AES Interceptor...")

    # Handle DB Update
    if args.update_db:
        print("[*] Updating Vulnerability Database...")
        updater = NVDUpdater()
        for lib in ["jquery", "bootstrap", "angularjs", "react", "vue", "crypto-js", "lodash", "moment"]:
            updater.update(lib, limit=15)
        print("[+] Vulnerability Database update complete.")
        if not args.url: sys.exit(0)

    # 0. Auto-Login (if requested)
    if args.login_url and args.username and args.password:
        login_manager = LoginManager(args.login_url, args.username, args.password)
        cookies_dict = login_manager.login()
        if cookies_dict:
            cookie_str = login_manager.get_cookie_string()
            print(f"[+] Auto-Login Cookie: {cookie_str}")
            if final_cookies:
                final_cookies += f"; {cookie_str}"
            else:
                final_cookies = cookie_str
        else:
            print("[-] Auto-Login failed to retrieve cookies.")

    # 1. Setup Session or Pool
    live_script = payload_path if args.live_exploit else None
    
    # We still need a single session to verify connection early
    test_session = SessionManager(
        cookies=final_cookies, 
        headers=args.headers, 
        ssl_verify=not args.insecure, 
        use_browser=False, # Verify quickly without browser
        live_exploit_script=live_script
    )
    if not test_session.verify_connection(args.url):
        print("[-] Connection failed or login invalid. Check URL/Cookies.")
        sys.exit(1)

    try:
        if args.browser:
            print(f"[*] Initializing WebDriver Pool with {args.threads} concurrent browsers...")
            session_manager_or_pool = WebDriverPool(
                size=args.threads,
                cookies=final_cookies,
                headers=args.headers,
                ssl_verify=not args.insecure,
                live_exploit_script=live_script
            )
            session_manager_or_pool.initialize()
        else:
            session_manager_or_pool = SessionManager(
                cookies=final_cookies, 
                headers=args.headers, 
                ssl_verify=not args.insecure, 
                use_browser=False,
                live_exploit_script=live_script
            )

        # 2. Crawl (Map)
        print(f"[*] Starting authenticated crawl on {args.url} (Depth: {args.depth}, Threads: {args.threads})...")
        discovery_findings = []
        crawler = Crawler(session_manager_or_pool, args.url, depth=args.depth, max_workers=args.threads)
        crawled_pages, network_urls, header_findings = crawler.start()
        print(f"[+] Found {len(crawled_pages)} unique pages/assets.")
        if network_urls:
            print(f"[+] Identified {len(network_urls)} unique assets via Network Logs.")
            
        if header_findings:
            print(f"[+] Found {len(header_findings)} missing security header issues.")
            discovery_findings.extend(header_findings)

        if args.save_content:
            os.makedirs("crawled_data", exist_ok=True)
            for url, content in crawled_pages.items():
                if len(url) > 100 or url.startswith("data:"):
                    filename = hashlib.md5(url.encode()).hexdigest() + ".content"
                else:
                    filename = url.replace("https://", "").replace("http://", "").replace("/", "_").replace("?", "_").replace("=", "_").replace(":", "_")
                
                try:
                    with open(os.path.join("crawled_data", filename), "w") as f:
                        f.write(content)
                except Exception as e:
                    print(f"[!] Warning: Could not save content for {url[:50]}... Error: {e}")
            print(f"[+] Saved content for {len(crawled_pages)} pages to 'crawled_data/'")

        

        # 3. Analyze (Engine)
        print("[*] Analyzing source code for vulnerabilities...")
        analyzer = Analyzer(vuln_db=vuln_db)
        findings = analyzer.scan(crawled_pages, network_urls)
        
        # Filter Findings (Severity)
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        min_score = severity_map.get(args.min_severity, 0)
        
        filtered_findings = [
            f for f in findings 
            if severity_map.get(f.get('severity', 'INFO'), 0) >= min_score
        ]
        
        if len(findings) > len(filtered_findings):
            print(f"[*] Filtered out {len(findings) - len(filtered_findings)} findings below {args.min_severity} severity.")

        # Filter Findings (Ignore List)
        if args.ignore_list and os.path.exists(args.ignore_list):
            try:
                with open(args.ignore_list, 'r') as f:
                    ignore_patterns = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                initial_count = len(filtered_findings)
                final_findings = []
                for finding in filtered_findings:
                    match_str = finding.get('match', '')
                    # Check if any ignore pattern is a substring of the match
                    if not any(pat in match_str for pat in ignore_patterns):
                        final_findings.append(finding)
                
                filtered_findings = final_findings
                if initial_count > len(filtered_findings):
                    print(f"[*] Filtered out {initial_count - len(filtered_findings)} findings matching the ignore list ({args.ignore_list}).")
            except Exception as e:
                print(f"[-] Failed to process ignore list: {e}")

        # 4. Report
        print("[*] Generating report...")
        reporter = Reporter(filtered_findings, verbose=args.verbose)
        reporter.print_summary()
        
        report_file = args.output if args.output else "vulcanx_report.html"
        reporter.save(report_file)
        
        try:
            import webbrowser
            report_path = f"file://{os.path.abspath(report_file)}"
            print(f"[*] Opening HTML report automatically in default browser...")
            webbrowser.open(report_path)
        except Exception as e:
            print(f"[-] Could not open browser automatically: {e}")
    finally:
        if args.browser and 'session_manager_or_pool' in locals() and session_manager_or_pool:
            session_manager_or_pool.close_all()
        elif not args.browser and 'session_manager_or_pool' in locals() and session_manager_or_pool:
            session_manager_or_pool.close()

if __name__ == "__main__":
    main()
