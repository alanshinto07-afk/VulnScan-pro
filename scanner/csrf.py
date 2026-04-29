"""CSRF scanner.

Inspects every form discovered by the crawler and flags any state-
changing form (POST or GET with non-idempotent action) that does not
have a recognizable anti-CSRF token. For forms that *do* contain a
token, we sample two requests for the form's page and compare token
values; if the token does not change between requests, randomness is
considered weak.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, Optional

from utils.crawler import FormInfo
from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


# Names commonly used for anti-CSRF tokens across frameworks.
TOKEN_NAME_PATTERN = re.compile(
    r"(csrf|xsrf|authenticity|nonce|token|_token|user_token)",
    re.IGNORECASE,
)

REMEDIATION = (
    "Add an unpredictable, per-session anti-CSRF token to all "
    "state-changing forms (typically a hidden input plus a server-side "
    "verification step). Use the SameSite=Lax/Strict cookie attribute. "
    "For APIs, require a custom header that browsers will not send "
    "cross-origin without a preflight."
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class CSRFScanner:
    name = "CSRF"

    def __init__(self, client: HttpClient, logger: Logger, ctx: ScanContext) -> None:
        self.client = client
        self.logger = logger
        self.ctx = ctx

    def run(self, forms: Iterable[FormInfo]) -> None:
        form_list = list(forms)
        total = max(len(form_list), 1)
        for idx, form in enumerate(form_list, start=1):
            self._scan_form(form)
            self.logger.progress(idx, total, label="CSRF")

    def _scan_form(self, form: FormInfo) -> None:
        # We only care about state-changing forms. POST is the obvious
        # case; GET forms are usually search/navigation and are fine.
        if form.method.upper() != "POST":
            return

        token_field = self._find_token_field(form)
        if token_field is None:
            self._record_missing(form)
            return

        # Re-fetch the page and compare the token.
        first = token_field.value or ""
        response = self.client.get(form.page_url)
        second_value: Optional[str] = None
        if response is not None:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(response.text, "html.parser")
            for candidate in soup.find_all("input"):
                name = candidate.get("name") or ""
                if name == token_field.name:
                    second_value = candidate.get("value") or ""
                    break

        if second_value is None or second_value == "":
            return

        if first == second_value:
            self._record_static(form, token_field.name, first)
        elif _shannon_entropy(second_value) < 2.5 or len(second_value) < 8:
            self._record_weak(form, token_field.name, second_value)

    def _find_token_field(self, form: FormInfo):
        for fld in form.inputs:
            if TOKEN_NAME_PATTERN.search(fld.name or ""):
                return fld
        return None

    def _record_missing(self, form: FormInfo) -> None:
        finding = Finding(
            module="csrf",
            name="Missing CSRF token",
            severity="MEDIUM",
            url=form.action,
            description=(
                f"The POST form on {form.page_url} (action={form.action}) "
                "does not contain a recognizable anti-CSRF token. An "
                "attacker can trick an authenticated user into submitting "
                "this form via a cross-origin request."
            ),
            evidence=f"Inputs: {[i.name for i in form.inputs]}",
            method=form.method,
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.vuln(f"Missing CSRF token on {form.action}")

    def _record_static(self, form: FormInfo, token_name: str, token_value: str) -> None:
        finding = Finding(
            module="csrf",
            name="Static / predictable CSRF token",
            severity="MEDIUM",
            url=form.action,
            description=(
                f"The CSRF token '{token_name}' on form {form.action} "
                "did not change between two consecutive page loads. A "
                "static token defeats the purpose of CSRF protection."
            ),
            evidence=f"Token value: {token_value}",
            payload=token_value,
            parameter=token_name,
            method=form.method,
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.vuln(f"Static CSRF token '{token_name}' on {form.action}")

    def _record_weak(self, form: FormInfo, token_name: str, token_value: str) -> None:
        finding = Finding(
            module="csrf",
            name="Low-entropy CSRF token",
            severity="MEDIUM",
            url=form.action,
            description=(
                f"The CSRF token '{token_name}' on form {form.action} "
                "appears to have insufficient randomness "
                f"(length={len(token_value)}, entropy={_shannon_entropy(token_value):.2f})."
            ),
            evidence=f"Token value: {token_value}",
            payload=token_value,
            parameter=token_name,
            method=form.method,
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.warning(f"Weak CSRF token '{token_name}' on {form.action}")
