"""VulnScan Pro - entry point.

Usage examples:
    python main.py -u http://localhost/dvwa
    python main.py -u http://localhost/dvwa --cookie "PHPSESSID=abc123"
    python main.py -u http://localhost/dvwa --sqli --xss
    python main.py -u http://localhost/dvwa --proxy http://127.0.0.1:8080
    python main.py -u http://localhost/dvwa --all --pdf

Disclaimer: For AUTHORIZED security testing only.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone

# Make sure the project root is on sys.path when executed directly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.crawler import Crawler
from utils.findings import ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger
from utils.reporter import (
    DISCLAIMER,
    write_html_report,
    write_json_report,
    write_pdf_report,
)

from scanner.csrf import CSRFScanner
from scanner.discovery import DiscoveryScanner
from scanner.fingerprint import fingerprint
from scanner.headers import HeadersScanner
from scanner.sqli import SQLiScanner
from scanner.traversal import TraversalScanner
from scanner.xss import XSSScanner


BANNER = r"""
__     __    _      ____                  ____            
\ \   / /   | |    / ___|  ___ __ _ _ __ |  _ \ _ __ ___  
 \ \ / /   _| |    \___ \ / __/ _` | '_ \| |_) | '__/ _ \ 
  \ V / |_| | |___  ___) | (_| (_| | | | |  __/| | | (_) |
   \_/ \__,_|_____|____/ \___\__,_|_| |_|_|   |_|  \___/  

           VulnScan Pro - Web App Vulnerability Scanner
                For AUTHORIZED testing only.
                Author : alan.sh
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="VulnScan Pro - modular web application vulnerability scanner.",
        epilog="For authorized testing only. Misuse is strictly prohibited.",
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://localhost/dvwa)")
    parser.add_argument("--cookie", help='Cookie string for authenticated scans (e.g. "PHPSESSID=abc; security=low")')
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080 for Burp Suite)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Minimum delay between requests (rate limiting)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2)")
    parser.add_argument("--max-pages", type=int, default=30, help="Maximum pages to crawl (default 30)")
    parser.add_argument("--no-rotate-ua", action="store_true", help="Disable user-agent rotation")
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS certificates (default off)")
    parser.add_argument("--output-dir", default="reports", help="Directory for generated reports")

    # Module toggles
    parser.add_argument("--all", action="store_true", help="Run all modules (default if no module flag is set)")
    parser.add_argument("--sqli", action="store_true", help="Run SQL Injection scanner")
    parser.add_argument("--xss", action="store_true", help="Run XSS scanner")
    parser.add_argument("--csrf", action="store_true", help="Run CSRF scanner")
    parser.add_argument("--traversal", action="store_true", help="Run directory traversal scanner")
    parser.add_argument("--headers", action="store_true", help="Run security headers scanner")
    parser.add_argument("--discovery", action="store_true", help="Run sensitive file discovery scanner")

    # Output toggles
    parser.add_argument("--html", action="store_true", help="Generate HTML report (default on)")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report")
    parser.add_argument("--json", action="store_true", help="Generate JSON report (default on)")
    parser.add_argument("--no-html", action="store_true", help="Disable HTML report")
    parser.add_argument("--no-json", action="store_true", help="Disable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Reduce terminal output")
    return parser.parse_args()


def select_modules(args: argparse.Namespace) -> dict:
    """Return a dict of module_name -> bool indicating whether to run."""
    flags = {
        "sqli": args.sqli,
        "xss": args.xss,
        "csrf": args.csrf,
        "traversal": args.traversal,
        "headers": args.headers,
        "discovery": args.discovery,
    }
    if args.all or not any(flags.values()):
        flags = {k: True for k in flags}
    return flags


def main() -> int:
    args = parse_args()
    print(BANNER)
    print(f"Target: {args.url}")
    print(f"Disclaimer: {DISCLAIMER}\n")

    logger = Logger(verbose=not args.quiet)
    payload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")

    client = HttpClient(
        cookie=args.cookie,
        proxy=args.proxy,
        timeout=args.timeout,
        min_delay=args.delay,
        rotate_ua=not args.no_rotate_ua,
        verify_tls=args.verify_tls,
    )

    started_dt = datetime.now(timezone.utc)
    started_str = started_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    ctx = ScanContext(target_url=args.url, started_at=started_str)
    start_time = time.monotonic()

    # ------------------------------------------------------------------
    # Pre-scan: fingerprint + crawl.
    # ------------------------------------------------------------------
    logger.info("Fingerprinting target...")
    fp = fingerprint(client, logger, args.url)
    ctx.metadata.update(fp)

    logger.info("Crawling target for pages and forms...")
    crawler = Crawler(client, logger, max_depth=args.depth, max_pages=args.max_pages)
    crawl_result = crawler.crawl(args.url)
    pages = crawl_result["pages"] or [args.url]
    forms = crawl_result["forms"]
    logger.success(f"Crawl complete: {len(pages)} page(s), {len(forms)} form(s) discovered")

    # ------------------------------------------------------------------
    # Run modules. Each module is wrapped in try/except so a single
    # failure does not abort the whole scan.
    # ------------------------------------------------------------------
    selected = select_modules(args)
    modules_run: list = []

    def _safe_run(name: str, runner) -> None:
        try:
            logger.info(f"--- Running module: {name} ---")
            runner()
            modules_run.append(name)
        except Exception as exc:  # noqa: BLE001 - we deliberately swallow
            logger.error(f"Module '{name}' failed: {exc!r}")

    if selected["sqli"]:
        sqli = SQLiScanner(client, logger, ctx, os.path.join(payload_dir, "sqli.txt"))
        _safe_run("sqli", lambda: sqli.run(pages, forms))

    if selected["xss"]:
        xss = XSSScanner(client, logger, ctx, os.path.join(payload_dir, "xss.txt"))
        _safe_run("xss", lambda: xss.run(pages, forms))

    if selected["csrf"]:
        csrf = CSRFScanner(client, logger, ctx)
        _safe_run("csrf", lambda: csrf.run(forms))

    if selected["traversal"]:
        trav = TraversalScanner(client, logger, ctx, os.path.join(payload_dir, "traversal.txt"))
        _safe_run("traversal", lambda: trav.run(pages))

    if selected["headers"]:
        hdr = HeadersScanner(client, logger, ctx)
        _safe_run("headers", lambda: hdr.run(args.url))

    if selected["discovery"]:
        disc = DiscoveryScanner(client, logger, ctx)
        _safe_run("discovery", lambda: disc.run(args.url))

    # ------------------------------------------------------------------
    # Wrap up + reports.
    # ------------------------------------------------------------------
    finished_dt = datetime.now(timezone.utc)
    ctx.finished_at = finished_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    ctx.metadata["modules"] = modules_run
    elapsed = time.monotonic() - start_time

    counts = ctx.severity_counts()
    total = sum(counts.values())
    logger.success(f"Scan complete in {elapsed:.1f}s | findings: {total}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        logger.info(f"  {sev}: {counts[sev]}")

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    safe_target = (
        args.url.replace("://", "_")
        .replace("/", "_")
        .replace(":", "_")
        .strip("_")
    )
    timestamp_tag = started_dt.strftime("%Y%m%d_%H%M%S")
    base_name = f"vulnscan_{safe_target}_{timestamp_tag}"

    want_html = not args.no_html
    want_json = not args.no_json
    want_pdf = args.pdf

    if want_html:
        html_path = write_html_report(ctx, os.path.join(output_dir, base_name + ".html"))
        logger.success(f"HTML report: {html_path}")
    if want_json:
        json_path = write_json_report(ctx, os.path.join(output_dir, base_name + ".json"))
        logger.success(f"JSON report: {json_path}")
    if want_pdf:
        pdf_path = write_pdf_report(ctx, os.path.join(output_dir, base_name + ".pdf"))
        if pdf_path:
            logger.success(f"PDF report: {pdf_path}")
        else:
            logger.warning("PDF generation requires fpdf2: pip install fpdf2")

    # Exit code: non-zero if any HIGH/CRITICAL was found, useful for CI.
    return 0 if counts["CRITICAL"] + counts["HIGH"] == 0 else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
