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
from utils.nvd_updater import NVDUpdater
from core.dorker import GoogleDorker
from core.discovery import PathEnumerator

def main():
    parser = argparse.ArgumentParser(description="VULSCAN - Advanced Web Application Source Code Scanner (Client-Side)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/dashboard)")
    parser.add_argument("-c", "--cookies", help="Session Cookies (e.g., 'sessionid=xyz; auth=abc')")
    parser.add_argument("-H", "--headers", action="append", help="Custom Headers (e.g., 'Authorization: Bearer token')")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawling Depth (default: 1)") # Reduced depth for testing
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)") # Reduced threads for testing
    parser.add_argument("-o", "--output", help="Output file (JSON/HTML)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL Verification")
    parser.add_argument("-b", "--browser", action="store_true", help="Use Headless Browser (Selenium) for crawling")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output for all findings")
    parser.add_argument("--save-content", action="store_true", help="Save all crawled content to local files")
    parser.add_argument("--min-severity", choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW', help="Minimum severity to report (default: LOW)")
    parser.add_argument("--update-db", action="store_true", help="Update the local vulnerability database from NVD")
    
    # Auto-Login Arguments
    parser.add_argument("--login-url", help="Login Page URL for Auto-Login")
    parser.add_argument("--username", help="Username for Auto-Login")
    parser.add_argument("--password", help="Password for Auto-Login")
    
    # New Strategies - Keeping for compatibility but will use custom logic below
    parser.add_argument("--live-exploit", action="store_true", help="Inject AES Interceptor and monitor for keys (Requires -b)")
    parser.add_argument("--scan-all", action="store_true", help="Run ALL strategies (Static, Dynamic) to find keys.")
    
    # Discovery Features
    parser.add_argument("--dorks", action="store_true", help="Generate and display Google Dorks, and dynamically execute them without API keys")
    parser.add_argument("--hidden-scan", action="store_true", help="Perform a directory brute-force scan to find hidden files/folders")
    parser.add_argument("--wordlist", help="Custom wordlist file for --hidden-scan (optional)")

    args = parser.parse_args()

    # Initialize DB & Cookies (Used by both normal and scan-all modes)
    print("[*] Initializing VULSCAN...")
    vuln_db = VulnerabilityDB()
    final_cookies = args.cookies

    # Force browser and save-content for this targeted scan
    args.browser = True
    args.save_content = True # Force save content locally

    # ------------------- TARGETED KEY SCAN LOGIC -------------------
    print("\n[PHASE 1] Targeted Static & Network Analysis (Crawling & Source Code Scan)...")

    # 0. Auto-Login (if requested) - Re-using existing logic
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

    # 1. Setup Session with Browser
    print("[*] Setting up browser session...")
    session_manager = SessionManager(
        cookies=final_cookies, 
        headers=args.headers, 
        ssl_verify=not args.insecure, 
        use_browser=True, # Always use browser for this targeted scan
        live_exploit_script=None # No live exploit for now, focusing on static
    )
    if not session_manager.verify_connection(args.url):
        print("[-] Connection failed or login invalid. Check URL/Cookies.")
        session_manager.close()
        sys.exit(1)

    try:
        # 2. Crawl (Map)
        print(f"[*] Starting authenticated crawl on {args.url} (Depth: {args.depth}, Threads: {args.threads})...")
        crawler = Crawler(session_manager, args.url, depth=args.depth, max_workers=args.threads)
        crawled_pages, network_urls = crawler.start()
        print(f"[+] Found {len(crawled_pages)} unique pages/assets.")
        if network_urls:
            print(f"[+] Identified {len(network_urls)} unique assets via Network Logs.")
        
        # Capture and analyze network logs specifically
        print("[*] Analyzing network logs for API responses and sensitive data...")
        network_responses = session_manager.get_network_logs()
        
        # Add network responses to crawled_pages for comprehensive static analysis
        for url, content in network_responses.items():
            if url not in crawled_pages: # Avoid overwriting content already crawled directly
                crawled_pages[url] = content

        # 3. Analyze (Engine)
        print("[*] Analyzing source code and network content for keys and vulnerabilities...")
        analyzer = Analyzer(vuln_db=vuln_db)
        findings = analyzer.scan(crawled_pages, network_urls)
        
        # Filter Findings
        severity_map = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        min_score = severity_map.get(args.min_severity, 0)
        
        filtered_findings = [
            f for f in findings 
            if severity_map.get(f.get('severity', 'INFO'), 0) >= min_score
        ]
        
        if len(findings) > len(filtered_findings):
            print(f"[*] Filtered out {len(findings) - len(filtered_findings)} findings below {args.min_severity} severity.")

        # 4. Report
        print("[*] Generating report...")
        reporter = Reporter(filtered_findings, verbose=args.verbose)
        reporter.print_summary()
        if args.output:
            reporter.save(args.output)
            
    finally:
        session_manager.close()

if __name__ == "__main__":
    main()
