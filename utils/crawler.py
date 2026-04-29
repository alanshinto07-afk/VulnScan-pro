"""Lightweight crawler that discovers links and forms on a target.

The crawler is intentionally conservative: it only follows links on the
same registered domain as the seed URL, respects a maximum depth and a
maximum number of pages, and returns structured form metadata that the
scanner modules can plug into directly.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlsplit

from bs4 import BeautifulSoup

from .http_client import HttpClient
from .logger import Logger


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class FormInfo:
    page_url: str
    action: str
    method: str
    inputs: List[FormField] = field(default_factory=list)

    def as_data(self, override: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build a dict of {name: value} suitable for posting the form."""
        data: Dict[str, str] = {}
        for fld in self.inputs:
            if not fld.name:
                continue
            data[fld.name] = fld.value or "test"
        if override:
            data.update(override)
        return data


class Crawler:
    """BFS crawler that yields visited pages and discovered forms."""

    def __init__(
        self,
        client: HttpClient,
        logger: Logger,
        max_depth: int = 2,
        max_pages: int = 30,
    ) -> None:
        self.client = client
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages

    @staticmethod
    def _same_host(seed: str, candidate: str) -> bool:
        a = urlsplit(seed)
        b = urlsplit(candidate)
        if not b.netloc:
            return True
        return a.netloc.lower() == b.netloc.lower()

    @staticmethod
    def _normalize(url: str) -> str:
        # Drop fragments to avoid revisiting the same page repeatedly.
        parts = urlsplit(url)
        return parts._replace(fragment="").geturl()

    def crawl(self, seed_url: str) -> Dict[str, List]:
        """Crawl the target and return discovered pages and forms."""
        visited: Set[str] = set()
        pages: List[str] = []
        forms: List[FormInfo] = []
        queue: deque = deque([(self._normalize(seed_url), 0)])

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            response = self.client.get(url)
            if response is None or response.status_code >= 400:
                continue
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                continue

            pages.append(url)
            self.logger.info(f"Crawled: {url}")

            soup = BeautifulSoup(response.text, "html.parser")

            # Collect forms on this page.
            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = (form.get("method") or "GET").upper()
                action_url = urljoin(url, action)
                inputs: List[FormField] = []
                for tag in form.find_all(["input", "textarea", "select"]):
                    name = tag.get("name")
                    if not name:
                        continue
                    inputs.append(
                        FormField(
                            name=name,
                            type=(tag.get("type") or tag.name or "text").lower(),
                            value=tag.get("value") or "",
                        )
                    )
                forms.append(
                    FormInfo(
                        page_url=url,
                        action=action_url,
                        method=method,
                        inputs=inputs,
                    )
                )

            # Enqueue links if we still have depth budget.
            if depth >= self.max_depth:
                continue
            for a in soup.find_all("a", href=True):
                next_url = self._normalize(urljoin(url, a["href"]))
                if not next_url.startswith(("http://", "https://")):
                    continue
                if not self._same_host(seed_url, next_url):
                    continue
                if next_url not in visited:
                    queue.append((next_url, depth + 1))

        return {"pages": pages, "forms": forms}
