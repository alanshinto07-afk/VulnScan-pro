"""SQL Injection scanner.

Strategy
========
For every URL parameter (GET) and every form input (POST), inject a
selection of payloads and look for one of the following signals:

1. **Error-based**: a database engine error message appears in the
   response (MySQL, MSSQL, Oracle, PostgreSQL, SQLite, etc.).
2. **Boolean-based**: a baseline response is captured first; injecting a
   tautology payload (``' OR '1'='1``) and a contradiction payload
   (``' AND '1'='2``) produces meaningfully different responses.

Findings are emitted with severity ``CRITICAL`` so they bubble to the
top of the report.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from utils.crawler import FormInfo
from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


# Database-specific error fragments that strongly suggest SQLi when they
# appear in a response that previously did not contain them.
DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"mysql_fetch_(array|assoc|object|row)", re.I),
    re.compile(r"supplied argument is not a valid mysql", re.I),
    re.compile(r"mysql server version for the right syntax", re.I),
    # PostgreSQL
    re.compile(r"pg_(query|exec)\(\)", re.I),
    re.compile(r"unterminated quoted string at or near", re.I),
    re.compile(r"postgresql.*error", re.I),
    # MSSQL
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"microsoft ole db provider for", re.I),
    re.compile(r"\[microsoft\]\[odbc sql server driver\]", re.I),
    re.compile(r"sql server.*incorrect syntax near", re.I),
    # Oracle
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"oracle.*driver", re.I),
    # SQLite
    re.compile(r"sqlite[._-]?error", re.I),
    re.compile(r"sqlite3::", re.I),
    re.compile(r"unrecognized token:", re.I),
    # Generic
    re.compile(r"odbc.*driver.*error", re.I),
    re.compile(r"jdbc.*sqlexception", re.I),
]

REMEDIATION = (
    "Use parameterized queries / prepared statements with bound "
    "parameters. Validate and whitelist input where possible. Apply "
    "least-privilege database accounts and disable verbose error pages "
    "in production."
)


def _load_payloads(path: str) -> List[str]:
    if not os.path.exists(path):
        return ["' OR 1=1--", "' OR '1'='1", "1' AND 1=1--", "1' AND 1=2--"]
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _matches_db_error(text: str) -> Optional[str]:
    for pattern in DB_ERROR_PATTERNS:
        m = pattern.search(text or "")
        if m:
            return m.group(0)
    return None


def _replace_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[name] = value
    return urlunsplit(parts._replace(query=urlencode(qs)))


class SQLiScanner:
    name = "SQL Injection"

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

    # ------------------------------------------------------------------
    def run(self, urls: Iterable[str], forms: Iterable[FormInfo]) -> None:
        url_list = list(urls)
        form_list = list(forms)
        total = max(len(url_list) + len(form_list), 1)
        done = 0

        for url in url_list:
            self._scan_url(url)
            done += 1
            self.logger.progress(done, total, label="SQLi")

        for form in form_list:
            self._scan_form(form)
            done += 1
            self.logger.progress(done, total, label="SQLi")

    # ------------------------------------------------------------------
    def _scan_url(self, url: str) -> None:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        if not params:
            return
        baseline = self.client.get(url)
        if baseline is None:
            return
        baseline_len = len(baseline.text or "")

        for param in params:
            if self._test_param(
                method="GET",
                url=url,
                param=param,
                send=lambda payload: self.client.get(_replace_query_param(url, param, payload)),
                baseline_len=baseline_len,
            ):
                # Stop at the first hit per parameter to avoid noise.
                continue

    def _scan_form(self, form: FormInfo) -> None:
        if not form.inputs:
            return
        baseline_data = form.as_data()
        if form.method == "POST":
            baseline = self.client.post(form.action, data=baseline_data)
        else:
            baseline = self.client.get(form.action, params=baseline_data)
        if baseline is None:
            return
        baseline_len = len(baseline.text or "")

        for fld in form.inputs:
            if not fld.name or fld.type in {"submit", "button", "image", "file", "hidden"}:
                continue

            def send(payload: str, _fld_name: str = fld.name) -> Optional[object]:
                payload_data = form.as_data(override={_fld_name: payload})
                if form.method == "POST":
                    return self.client.post(form.action, data=payload_data)
                return self.client.get(form.action, params=payload_data)

            self._test_param(
                method=form.method,
                url=form.action,
                param=fld.name,
                send=send,
                baseline_len=baseline_len,
            )

    # ------------------------------------------------------------------
    def _test_param(
        self,
        method: str,
        url: str,
        param: str,
        send,
        baseline_len: int,
    ) -> bool:
        # Phase 1: error-based detection
        for payload in self.payloads:
            response = send(payload)
            if response is None:
                continue
            err = _matches_db_error(response.text or "")
            if err:
                self._record(method, url, param, payload, response.text, err)
                return True

        # Phase 2: boolean-based detection
        truthy = send("' OR '1'='1")
        falsy = send("' AND '1'='2")
        if truthy is not None and falsy is not None:
            t_len = len(truthy.text or "")
            f_len = len(falsy.text or "")
            # We want truthy to look more like baseline than falsy does.
            # Heuristic: large length difference between truthy and falsy
            # AND truthy close to baseline.
            if abs(t_len - f_len) > 50 and abs(t_len - baseline_len) < abs(f_len - baseline_len):
                self._record(
                    method,
                    url,
                    param,
                    payload="' OR '1'='1 vs ' AND '1'='2",
                    body_text=(truthy.text or "")[:500],
                    evidence_extra=(
                        f"Boolean-based: baseline={baseline_len}B, "
                        f"truthy={t_len}B, falsy={f_len}B"
                    ),
                )
                return True
        return False

    # ------------------------------------------------------------------
    def _record(
        self,
        method: str,
        url: str,
        param: str,
        payload: str,
        body_text: str,
        evidence_extra: str = "",
    ) -> None:
        snippet = (body_text or "")[:600]
        evidence = snippet
        if evidence_extra:
            evidence = f"{evidence_extra}\n---\n{snippet}"
        finding = Finding(
            module="sqli",
            name="SQL Injection",
            severity="CRITICAL",
            url=url,
            description=(
                f"Parameter '{param}' on {method} {url} is vulnerable to SQL "
                "injection. The application reflects database-level errors "
                "or differential responses when SQL metacharacters are sent."
            ),
            evidence=evidence,
            payload=payload,
            parameter=param,
            method=method,
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.vuln(f"SQLi confirmed at {method} {url} param={param}")
