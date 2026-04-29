# VulnScan Pro

A modular **Web Application Vulnerability Scanner** written in Python 3,
designed for **authorized** security testing of web applications such as
**DVWA (Damn Vulnerable Web Application)**, bWAPP, WebGoat, or your own
applications.

> ⚠️  **Disclaimer — For authorized testing only.** Running this tool
> against a target you do not own or have explicit written permission to
> test is illegal in most jurisdictions. The author and contributors
> accept no liability for misuse.

---

## Features

| Module                  | Severity   | What it does                                                         |
|-------------------------|------------|----------------------------------------------------------------------|
| SQL Injection           | CRITICAL   | Error-based + boolean-based detection across GET/POST parameters     |
| XSS (Reflected/Stored)  | HIGH       | Unique-marker payload reflection check across GET/POST               |
| CSRF                    | MEDIUM     | Detects missing tokens, static tokens, and low-entropy tokens        |
| Directory Traversal     | MEDIUM     | Tests path traversal in URL parameters and selected headers         |
| Sensitive File Discovery| INFO       | Probes 40+ known sensitive paths (`.env`, `.git/config`, etc.)       |
| HTTP Security Headers   | LOW        | Checks for `CSP`, `HSTS`, `X-Frame-Options`, etc.                    |

Plus:

- **ASCII banner** on startup
- **Real-time progress bars** and color-coded terminal output
- **Time-elapsed counter**, total findings counter, severity breakdown
- **Cookie-based authentication** for scanning logged-in pages
- **Proxy support** (use `--proxy http://127.0.0.1:8080` to route through Burp Suite)
- **User-agent rotation** and **per-request rate limiting**
- **WAF detection** (Cloudflare, Akamai, AWS WAF, Sucuri, Imperva, F5, ModSecurity, Barracuda, Wallarm…)
- **Server / technology fingerprinting** (PHP, WordPress, Django, Laravel, etc.)
- **HTML, PDF, JSON** report generation with a professional dark theme

---

## Project Structure

```
vuln_scanner/
├── main.py                 # entry point (argparse, orchestrator)
├── requirements.txt
├── README.md
├── scanner/
│   ├── sqli.py             # SQL Injection scanner
│   ├── xss.py              # Reflected & Stored XSS scanner
│   ├── csrf.py             # CSRF token scanner
│   ├── traversal.py        # Directory traversal scanner
│   ├── headers.py          # HTTP security headers scanner
│   ├── discovery.py        # Sensitive file discovery scanner
│   └── fingerprint.py      # Server / tech / WAF fingerprinting
├── utils/
│   ├── crawler.py          # Form & link crawler
│   ├── http_client.py      # Shared rate-limited HTTP client
│   ├── findings.py         # Finding / ScanContext dataclasses
│   ├── logger.py           # Colored, thread-safe, timestamped logger
│   └── reporter.py         # HTML / PDF / JSON report writers
├── payloads/
│   ├── sqli.txt
│   ├── xss.txt
│   └── traversal.txt
└── reports/                # Reports are written here
```

---

## Installation

VulnScan Pro requires **Python 3.9+**.

```bash
git clone <your-fork-or-zip>
cd vuln_scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Dependencies (see `requirements.txt`):

- `requests` — HTTP client
- `beautifulsoup4` — HTML parsing for the crawler and CSRF scanner
- `colorama` — cross-platform colored terminal output
- `fpdf2` — pure-Python PDF generation (no external binary needed)
- `urllib3` — required transitively; pinned to silence TLS warnings

---

## Quick Start

### 1. Spin up DVWA (or any authorized target)

The fastest way to try VulnScan Pro is to run DVWA in Docker:

```bash
docker run --rm -d -p 8080:80 vulnerables/web-dvwa
# DVWA is now at http://localhost:8080
# Default credentials: admin / password
# Visit /setup.php once to initialize the database.
```

### 2. Grab a session cookie

After logging in to DVWA in your browser, copy the `PHPSESSID` and
`security` cookies from your browser DevTools.

### 3. Run a scan

```bash
# Basic scan (anonymous)
python main.py -u http://localhost:8080

# Authenticated scan against DVWA
python main.py -u http://localhost:8080/vulnerabilities/sqli/ \
    --cookie "PHPSESSID=<your_id>; security=low"

# Specific modules only
python main.py -u http://localhost:8080 --sqli --xss

# Route everything through Burp Suite
python main.py -u http://localhost:8080 --proxy http://127.0.0.1:8080

# Full scan with PDF report
python main.py -u http://localhost:8080 --all --pdf
```

Reports are written to the `reports/` directory:

```
reports/vulnscan_http_localhost_8080_20240429_010203.html
reports/vulnscan_http_localhost_8080_20240429_010203.json
reports/vulnscan_http_localhost_8080_20240429_010203.pdf
```

---

## Command-line Reference

```text
usage: vulnscan [-h] -u URL [--cookie COOKIE] [--proxy PROXY]
                [--timeout TIMEOUT] [--delay DELAY] [--depth DEPTH]
                [--max-pages MAX_PAGES] [--no-rotate-ua] [--verify-tls]
                [--output-dir OUTPUT_DIR] [--all] [--sqli] [--xss]
                [--csrf] [--traversal] [--headers] [--discovery]
                [--html] [--pdf] [--json] [--no-html] [--no-json]
                [--quiet]
```

Highlights:

| Flag                | Meaning                                                              |
|---------------------|----------------------------------------------------------------------|
| `-u, --url`         | Target URL (required)                                                |
| `--cookie`          | Session cookie(s) for authenticated scans                            |
| `--proxy`           | HTTP/HTTPS proxy (e.g. Burp Suite at `http://127.0.0.1:8080`)        |
| `--delay`           | Minimum seconds between requests (default 0.5)                       |
| `--timeout`         | Per-request timeout in seconds (default 10)                          |
| `--depth`           | Crawl depth (default 2)                                              |
| `--max-pages`       | Max pages to crawl (default 30)                                      |
| `--all`             | Run every module (this is also the default when no module is given)  |
| `--sqli/--xss/...`  | Run only specific modules                                            |
| `--pdf`             | Also produce a PDF report                                            |
| `--no-html`         | Disable HTML report                                                  |
| `--no-json`         | Disable JSON report                                                  |
| `--no-rotate-ua`    | Disable random user-agent rotation                                   |

Exit codes:

- `0` — scan completed, no `HIGH` or `CRITICAL` findings
- `2` — scan completed, at least one `HIGH` or `CRITICAL` finding (useful for CI)
- `130` — interrupted with Ctrl+C

---

## Severity & CVSS

Each finding is tagged with a severity and an approximate CVSS v3.1 score:

| Severity   | Default CVSS | Default cause                                                  |
|------------|--------------|----------------------------------------------------------------|
| CRITICAL   | 9.8          | SQL Injection                                                  |
| HIGH       | 7.5          | XSS (Reflected / Stored)                                       |
| MEDIUM     | 5.4          | CSRF (missing/static/weak token), Directory traversal          |
| LOW        | 3.1          | Missing security headers                                       |
| INFO       | 0.0          | Sensitive paths exposed                                        |

These defaults are deliberately conservative; tune them in
`utils/findings.py` (`DEFAULT_CVSS`) if your environment requires it.

---

## Adding a new module

1. Create `scanner/<your_module>.py`. The class must accept
   `(client, logger, ctx)` (plus any optional payload file) and expose a
   `run(...)` method.
2. In `run`, append `Finding(...)` objects to `ctx`.
3. Wire it into `main.py`:
   - add an `--your-module` flag,
   - add the key to `select_modules`,
   - call your scanner inside `_safe_run("your_module", ...)`.
4. Add any payload file under `payloads/`.

The reporter does not need to change — every module shares the same
`Finding` schema.

---

## Operational notes

- **Rate limiting** defaults to a 0.5 s gap between requests. Increase
  `--delay` when scanning fragile applications or when a WAF is
  rate-limiting you.
- **Authentication**: only cookie-based auth is built in. For
  HTTP-Basic or token-based APIs, extend `HttpClient` to add the right
  headers — the rest of the codebase will pick them up automatically.
- **Burp Suite integration**: pass `--proxy http://127.0.0.1:8080` and
  every request — including authenticated ones — flows through Burp.
- **CI usage**: `python main.py -u $TARGET --all --no-html` exits with
  code 2 if any HIGH/CRITICAL is found. Combine with the JSON report to
  fail your pipeline on regressions.

---

## Legal

By using VulnScan Pro you agree that you have explicit, written
authorization to test the target system. Unauthorized testing is
illegal under laws including the US Computer Fraud and Abuse Act, the
UK Computer Misuse Act, the EU Directive 2013/40/EU, and equivalents in
other jurisdictions. Always operate within your scope of engagement.
