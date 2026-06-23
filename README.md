# VulcanX

VulcanX is an advanced, enterprise-grade, client-side web application vulnerability scanner tailored for manual bug bounty hunters and penetration testers. It focuses on finding critical vulnerabilities, hardcoded secrets, and hidden attack surface in heavily obfuscated, modern Single-Page Applications (React, Vue, Angular).

## Core Features

- **Automated Source Map Recompilation:** Automatically detects `.map` files, downloads them, and reconstructs the unminified original source code into virtual memory for deep static analysis.
- **Deep Static Taint Analysis:** Traces data flows from unsafe sources (e.g., `location.search`) to dangerous sinks (e.g., `innerHTML`) to identify DOM XSS vulnerabilities entirely statically.
- **Automated API & Parameter Mapping:** Parses JS routing logic (e.g., `fetch`, `axios`) to dynamically extract hidden backend API routes and their expected JSON parameters.
- **Advanced JWT Offline Analysis:** Automatically decodes discovered JSON Web Tokens, extracts tenant data, and flags CRITICAL weaknesses like the `'alg': 'none'` signature bypass.
- **Wayback Machine & OSINT Passive Recon:** Queries the Internet Archive's CDX API, AlienVault OTX, and crt.sh to discover subdomains, historical endpoints, and forgotten APIs without touching the target.
- **Advanced Deobfuscation Engine:** Includes dynamic AES interception and AST-based deobfuscation to decrypt payloads and extract hardcoded keys disguised within complex JavaScript logic.
- **Targeted Discovery:** Features an extensive brute-force engine targeting over 40 distinct Swagger/OpenAPI documentation paths, configuration files, and sensitive directories.
- **Bug Bounty Signatures:** Equipped with high-confidence regex signatures tailored for bug bounties (e.g., Stripe Keys, GitHub PATs, Firebase URLs, SSRF URL Parameters, S3 Buckets, Hardcoded Bearer Tokens).
- **False Positive Triage:** Supports `.vulcanxignore` files to easily filter out known, intentional dummy keys or safe strings across repeated scans.
- **Enterprise Reporting:** Generates interactive, standalone HTML dashboards with graphical severity distributions, confidence scores, and industry compliance mapping (OWASP, PCI-DSS, ISO 27001).

## Usage

Basic comprehensive scan:
```bash
python3 vulcanx.py -u https://target.com --scan-all
```

Targeted Secret Hunting with False Positive Filtering:
```bash
python3 vulcanx.py -u https://target.com --key-and-file-scan-only --ignore-list ignore.txt
```

Aggressive Discovery (Hidden Paths & Swagger API Docs):
```bash
python3 vulcanx.py -u https://target.com --hidden-scan --wordlist custom_list.txt
```

Live Deobfuscation (Requires Headless Browser):
```bash
python3 vulcanx.py -u https://target.com -b --live-exploit
```

## Options

* `-u, --url`: Target URL
* `-c, --cookies`: Session Cookies for authenticated scanning
* `-H, --headers`: Custom headers (e.g., Authorization tokens)
* `-d, --depth`: Crawl depth (Default: 3)
* `-t, --threads`: Concurrent threads for crawling/bruteforcing (Default: 10)
* `--ignore-list`: Path to a text file containing strings/regexes to ignore
* `--min-severity`: Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)
* `-o, --output`: Output file name for the HTML report
* `--dorks`: Generate and execute Google Dorks for the target domain