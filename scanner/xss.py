"""Reflected / stored XSS scanner.

For every parameter and form input, the scanner submits a unique marker
payload and looks for the *exact* marker reflected verbatim in the
response body. Using a marker (rather than the payload itself) avoids
false positives from sanitization that just escapes a generic
``<script>`` payload.

Stored XSS is approximated by re-fetching the form's page after
submission and checking for the marker on the new response — this
catches the common case of guestbooks, comment fields, or DVWA's
"Stored XSS" lab.
"""
from __future__ import annotations

import os
import secrets
from typing import Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from utils.crawler import FormInfo
from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


REMEDIATION = (
    "Apply context-aware output encoding (HTML, attribute, JavaScript, "
    "URL). Use a strict Content-Security-Policy. Validate and reject "
    "input containing HTML/JS where it is not expected. Frameworks like "
    "React/Angular auto-escape - avoid using innerHTML / dangerouslySetInnerHTML."
)


def _load_payloads(path: str) -> List[str]:
    if not os.path.exists(path):
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _replace_query_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[name] = value
    return urlunsplit(parts._replace(query=urlencode(qs)))


class XSSScanner:
    name = "Cross-Site Scripting"

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
            self.logger.progress(done, total, label="XSS")

        for form in form_list:
            self._scan_form(form)
            done += 1
            self.logger.progress(done, total, label="XSS")

    # ------------------------------------------------------------------
    def _scan_url(self, url: str) -> None:
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        for param in params:
            for payload in self.payloads:
                marker = f"vsx{secrets.token_hex(4)}"
                injected = payload.replace("XSS", marker).replace("alert(1)", f"alert('{marker}')")
                test_url = _replace_query_param(url, param, injected)
                response = self.client.get(test_url)
                if response is None:
                    continue
                if marker in (response.text or ""):
                    self._record(
                        kind="Reflected XSS",
                        method="GET",
                        url=test_url,
                        param=param,
                        payload=injected,
                        body=response.text,
                    )
                    break

    def _scan_form(self, form: FormInfo) -> None:
        if not form.inputs:
            return
        for fld in form.inputs:
            if not fld.name or fld.type in {"submit", "button", "image", "file", "hidden"}:
                continue
            for payload in self.payloads:
                marker = f"vsx{secrets.token_hex(4)}"
                injected = payload.replace("XSS", marker).replace("alert(1)", f"alert('{marker}')")
                data = form.as_data(override={fld.name: injected})
                if form.method == "POST":
                    response = self.client.post(form.action, data=data)
                else:
                    response = self.client.get(form.action, params=data)
                if response is None:
                    continue
                if marker in (response.text or ""):
                    self._record(
                        kind="Reflected XSS",
                        method=form.method,
                        url=form.action,
                        param=fld.name,
                        payload=injected,
                        body=response.text,
                    )
                    # Check for stored XSS by re-fetching the form's page.
                    stored_resp = self.client.get(form.page_url)
                    if stored_resp is not None and marker in (stored_resp.text or ""):
                        self._record(
                            kind="Stored XSS",
                            method=form.method,
                            url=form.page_url,
                            param=fld.name,
                            payload=injected,
                            body=stored_resp.text,
                        )
                    break

    # ------------------------------------------------------------------
    def _record(
        self,
        kind: str,
        method: str,
        url: str,
        param: str,
        payload: str,
        body: Optional[str],
    ) -> None:
        snippet = (body or "")[:600]
        finding = Finding(
            module="xss",
            name=kind,
            severity="HIGH",
            url=url,
            description=(
                f"{kind}: parameter '{param}' on {method} {url} reflects "
                "the supplied payload in the response without proper "
                "encoding. An attacker can execute JavaScript in the "
                "victim's browser context."
            ),
            evidence=snippet,
            payload=payload,
            parameter=param,
            method=method,
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.vuln(f"{kind} confirmed at {method} {url} param={param}")
