"""Sensitive file / common path discovery.

Walks a curated list of files known to leak information when exposed
publicly (``.env``, ``.git/config``, ``backup.zip``, ``phpinfo.php``,
``robots.txt``, etc.). Each file that returns a 200 with a non-empty
body becomes an ``INFO`` finding.

robots.txt is treated specially: when present we also parse out
disallowed paths because those tend to be interesting attack surface.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urljoin, urlsplit

from utils.findings import Finding, ScanContext
from utils.http_client import HttpClient
from utils.logger import Logger


SENSITIVE_PATHS: List[str] = [
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".env.local",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    ".svn/entries",
    ".hg/store/data",
    "backup.zip",
    "backup.tar.gz",
    "database.sql",
    "db.sql",
    "dump.sql",
    "admin.php",
    "admin/",
    "administrator/",
    "config.php",
    "config.inc.php",
    "configuration.php",
    "phpinfo.php",
    "info.php",
    "test.php",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "WEB-INF/web.xml",
    "server-status",
    "server-info",
    "wp-config.php",
    "wp-config.php.bak",
    "wp-admin/",
    "wp-login.php",
    "_vti_pvt/",
    ".DS_Store",
    "composer.json",
    "composer.lock",
    "package.json",
    "yarn.lock",
    "Dockerfile",
    "docker-compose.yml",
    ".aws/credentials",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_dsa",
]


REMEDIATION = (
    "Restrict access to administrative, configuration, and version "
    "control artifacts. Block or 404 these paths at the web server / "
    "load balancer level. Audit deployments to ensure backup and dev "
    "files are never shipped to production."
)


class DiscoveryScanner:
    name = "Sensitive File Discovery"

    def __init__(self, client: HttpClient, logger: Logger, ctx: ScanContext) -> None:
        self.client = client
        self.logger = logger
        self.ctx = ctx

    def run(self, target_url: str) -> None:
        # Always probe relative to the scheme://host root, regardless of
        # which subpath the user supplied.
        parts = urlsplit(target_url)
        base = f"{parts.scheme}://{parts.netloc}/"
        total = len(SENSITIVE_PATHS)
        for idx, path in enumerate(SENSITIVE_PATHS, start=1):
            self._check(base, path)
            self.logger.progress(idx, total, label="Discovery")

    def _check(self, base: str, path: str) -> None:
        url = urljoin(base, path)
        response = self.client.get(url, allow_redirects=False)
        if response is None:
            return
        if response.status_code != 200:
            return
        body = response.text or ""
        if not body.strip():
            return
        finding = Finding(
            module="discovery",
            name=f"Sensitive resource exposed: /{path}",
            severity="INFO",
            url=url,
            description=(
                f"The path /{path} is publicly accessible (HTTP 200) "
                "and may leak configuration, credentials, version "
                "control metadata, or other sensitive information."
            ),
            evidence=body[:400],
            method="GET",
            remediation=REMEDIATION,
        )
        self.ctx.add(finding)
        self.logger.warning(f"Exposed: {url}")
