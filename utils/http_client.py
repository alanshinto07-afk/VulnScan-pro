"""Shared HTTP client used by every scanner module.

Centralizing requests in one place means the rest of the codebase
gets the same behavior for free: rate limiting, timeouts, proxy
support, user-agent rotation, retries, and graceful exception
handling. Modules should never call ``requests`` directly.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Any, Dict, Optional

import requests
from requests import Response
from requests.exceptions import RequestException

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
]


class HttpClient:
    """Thin wrapper around ``requests.Session`` with safety rails.

    Important behaviors:
      * Rate limiting via ``min_delay`` between any two requests.
      * Per-request timeout with sane default.
      * Optional proxy (e.g. Burp Suite at http://127.0.0.1:8080).
      * Cookie-based auth via the ``cookie`` constructor arg.
      * Random user-agent rotation per request when enabled.
      * Never raises on network failures: callers receive ``None``.
    """

    def __init__(
        self,
        cookie: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: float = 10.0,
        min_delay: float = 0.5,
        rotate_ua: bool = True,
        verify_tls: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.session = requests.Session()
        self.timeout = timeout
        self.min_delay = min_delay
        self.rotate_ua = rotate_ua
        self.verify_tls = verify_tls
        self._lock = threading.Lock()
        self._last_request_time = 0.0

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        if cookie:
            # Allow either "name=value" or "name1=value1; name2=value2".
            for part in cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.session.cookies.set(name.strip(), value.strip())

        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        if extra_headers:
            base_headers.update(extra_headers)
        self.session.headers.update(base_headers)

        # Disable noisy InsecureRequestWarning when verify_tls is False.
        if not verify_tls:
            try:
                from urllib3.exceptions import InsecureRequestWarning
                import urllib3

                urllib3.disable_warnings(InsecureRequestWarning)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _respect_rate_limit(self) -> None:
        """Sleep just enough to honor ``min_delay`` between requests."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
            self._last_request_time = time.monotonic()

    def _build_headers(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        merged: Dict[str, str] = {}
        if self.rotate_ua:
            merged["User-Agent"] = random.choice(DEFAULT_USER_AGENTS)
        if headers:
            merged.update(headers)
        return merged

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        """Perform an HTTP request and return the response or ``None``.

        Network errors are swallowed and reported as ``None`` so a single
        failure inside one module never aborts the whole scan.
        """
        self._respect_rate_limit()
        try:
            return self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=self._build_headers(headers),
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_tls,
            )
        except RequestException:
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[Response]:
        return self.request("POST", url, **kwargs)
