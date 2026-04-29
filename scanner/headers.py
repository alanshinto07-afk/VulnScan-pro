"""HTTP security headers scanner.

Issues a single GET to the target and reports any of the commonly-
recommended security headers that are missing or weak. Each missing
header becomes a separate ``LOW`` finding so they are easy to triage.
"""
from __future__ import annotations

from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


HEADERS_TO_CHECK = {
    "X-Frame-Options": (
        "Prevents the page from being framed by other origins (clickjacking).",
        "Set to 'SAMEORIGIN' or 'DENY', or rely on a 'frame-ancestors' CSP directive.",
    ),
    "Content-Security-Policy": (
        "Restricts resource origins and is the strongest defense against XSS.",
        "Define a strict CSP appropriate for your app; start with 'default-src self'.",
    ),
    "X-XSS-Protection": (
        "Legacy browser XSS filter. Modern browsers ignore it but it is still "
        "checked by compliance tooling.",
        "Set to '0' if you have a strong CSP, or '1; mode=block' for legacy clients.",
    ),
    "Strict-Transport-Security": (
        "Forces browsers to use HTTPS for the configured domain.",
        "Set 'max-age=31536000; includeSubDomains; preload' on HTTPS endpoints.",
    ),
    "X-Content-Type-Options": (
        "Disables MIME-type sniffing.",
        "Set to 'nosniff'.",
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is leaked.",
        "Set to 'strict-origin-when-cross-origin' or stricter.",
    ),
    "Permissions-Policy": (
        "Restricts browser features the page can use.",
        "Define a Permissions-Policy that disables unused features (camera, geolocation, etc.).",
    ),
}


class HeadersScanner:
    name = "Security Headers"

    def __init__(self, client: HttpClient, logger: Logger, ctx: ScanContext) -> None:
        self.client = client
        self.logger = logger
        self.ctx = ctx

    def run(self, target_url: str) -> None:
        response = self.client.get(target_url)
        if response is None:
            self.logger.warning("Headers scan: no response from target")
            return
        headers = {k.lower(): v for k, v in response.headers.items()}

        for header, (description, fix) in HEADERS_TO_CHECK.items():
            value = headers.get(header.lower())
            if value:
                self.logger.success(f"{header}: {value}")
                continue
            finding = Finding(
                module="headers",
                name=f"Missing header: {header}",
                severity="LOW",
                url=target_url,
                description=f"Response is missing the '{header}' header. {description}",
                evidence=f"Response headers: {dict(response.headers)}",
                remediation=fix,
            )
            self.ctx.add(finding)
            self.logger.warning(f"Missing header: {header}")
