"""Path / directory traversal scanner.

Checks whether any URL parameter or any of a small set of common
headers (``X-Original-URL``, ``Referer``) lets an attacker read files
outside the document root. The detection signal is the presence of
canonical file markers (``root:x:0:0`` from ``/etc/passwd``, or the
``[fonts]`` / ``[extensions]`` sections in Windows ``win.ini``).
"""
from __future__ import annotations

import os
import re
from typing import Iterable, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


PASSWD_PATTERN = re.compile(r"root:[x*]?:0:0:")
WIN_INI_PATTERN = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)

REMEDIATION = (
    "Never pass user input directly to file system APIs. Resolve and "
    "canonicalize paths, then verify they remain inside an allowlisted "
    "base directory. Reject input containing '..', NUL bytes, or "
    "absolute paths. Run the application with least-privilege FS access."
)


def _load_payloads(path: str) -> List[str]:
    if not os.path.exists(path):
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
        ]
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _replace_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[name] = value
    return urlunsplit(parts._replace(query=urlencode(qs)))


class TraversalScanner:
    name = "Directory Traversal"

    def __init__(
        self,
        client: HttpClient,
        logger: Logger,
        ctx: ScanContext,
        payload_file: str,
    ) -> None:
        self.client = client
        self.logger = logger
        self.ctx = ctx
        self.payloads = _load_payloads(payload_file)

    def run(self, urls: Iterable[str]) -> None:
        url_list = list(urls)
        total = max(len(url_list) * 2, 1)
        done = 0
        for url in url_list:
            self._scan_query(url)
            done += 1
            self.logger.progress(done, total, label="Traversal")
            self._scan_headers(url)
            done += 1
            self.logger.progress(done, total, label="Traversal")

    # ------------------------------------------------------------------
    def _scan_query(self, url: str) -> None:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        if not params:
            return
        for param in params:
            for payload in self.payloads:
                test_url = _replace_query_param(url, param, payload)
                response = self.client.get(test_url)
                if response is None:
                    continue
                hit = self._matches(response.text or "")
                if hit:
                    self._record("query", test_url, param, payload, response.text, hit)
                    break

    def _scan_headers(self, url: str) -> None:
        # Only meaningful for endpoints that echo headers back; we still
        # try a couple of common candidates to catch misconfigured
        # routing layers.
        for header_name in ("X-Original-URL", "X-Rewrite-URL", "Referer"):
            for payload in self.payloads[:5]:  # limit noise
                response = self.client.get(url, headers={header_name: payload})
                if response is None:
                    continue
                hit = self._matches(response.text or "")
                if hit:
                    self._record(
                        "header",
                        url,
                        header_name,
                        payload,
                        response.text,
                        hit,
                    )
                    return

    def _matches(self, text: str):
        if PASSWD_PATTERN.search(text):
            return "Linux /etc/passwd content detected"
        if WIN_INI_PATTERN.search(text):
            return "Windows win.ini content detected"
        return None

    def _record(
        self,
        location: str,
        url: str,
        param: str,
        payload: str,
        body: str,
        evidence_label: str,
    ) -> None:
        snippet = (body or "")[:600]
        finding = Finding(
            module="traversal",
            name="Directory Traversal",
            severity="MEDIUM",
            url=url,
            description=(
                f"Path traversal via {location} parameter '{param}'. "
                f"{evidence_label}."
            ),
            evidence=f"{evidence_label}\n---\n{snippet}",
            payload=payload,
            parameter=param,
            method="GET",
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.vuln(f"Directory traversal at {url} param={param}")
