"""Lightweight server / technology / WAF fingerprinting.

This is intentionally heuristic: there are full products (Wappalyzer,
WhatWeb, wafw00f) that do this much better. The goal here is just to
populate the report metadata so the user has context.
"""
from __future__ import annotations

from typing import Dict, List

from utils.http_client import HttpClient
from utils.logger import Logger


# Header / cookie / body signatures that strongly indicate a particular
# WAF. Order matters: first match wins.
WAF_SIGNATURES: List[Dict[str, str]] = [
    {"name": "Cloudflare", "header": "server", "value": "cloudflare"},
    {"name": "Cloudflare", "header": "cf-ray", "value": ""},
    {"name": "AWS WAF", "header": "x-amzn-requestid", "value": ""},
    {"name": "AWS WAF", "header": "x-amz-cf-id", "value": ""},
    {"name": "Akamai", "header": "server", "value": "akamaighost"},
    {"name": "Sucuri", "header": "x-sucuri-id", "value": ""},
    {"name": "Sucuri", "header": "server", "value": "sucuri"},
    {"name": "Imperva Incapsula", "header": "x-iinfo", "value": ""},
    {"name": "Imperva Incapsula", "header": "x-cdn", "value": "incapsula"},
    {"name": "F5 BIG-IP", "header": "server", "value": "big-ip"},
    {"name": "F5 BIG-IP", "header": "x-waf-event-info", "value": ""},
    {"name": "ModSecurity", "header": "server", "value": "mod_security"},
    {"name": "Barracuda", "header": "server", "value": "barracuda"},
    {"name": "Wallarm", "header": "x-wallarm", "value": ""},
]


# Body / header fingerprints for common application stacks.
TECH_SIGNATURES = [
    ("X-Powered-By", None, "X-Powered-By header"),
    ("Server", None, "Server header"),
]


def _header_lower(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def fingerprint(client: HttpClient, logger: Logger, target_url: str) -> Dict[str, str]:
    """Return a dict with keys server, technology, waf."""
    info = {"server": "Unknown", "technology": "Unknown", "waf": "Not detected"}

    response = client.get(target_url)
    if response is None:
        logger.warning("Fingerprint: could not reach target")
        return info

    headers = _header_lower(response.headers)
    body = response.text or ""

    info["server"] = headers.get("server", "Unknown")
    powered = headers.get("x-powered-by")
    tech_parts = []
    if powered:
        tech_parts.append(powered)
    if "wp-content" in body or "wp-includes" in body:
        tech_parts.append("WordPress")
    if "drupal" in body.lower():
        tech_parts.append("Drupal")
    if "joomla" in body.lower():
        tech_parts.append("Joomla")
    if "phpsessid" in (response.cookies.get_dict() and ",".join(response.cookies.keys()).lower() or ""):
        tech_parts.append("PHP")
    if "django" in body.lower() or "csrfmiddlewaretoken" in body:
        tech_parts.append("Django")
    if "laravel_session" in (response.cookies.get_dict() and ",".join(response.cookies.keys()).lower() or ""):
        tech_parts.append("Laravel")
    if tech_parts:
        info["technology"] = ", ".join(sorted(set(tech_parts)))

    # WAF detection from headers.
    for sig in WAF_SIGNATURES:
        h_name = sig["header"].lower()
        h_val = sig["value"].lower()
        actual = headers.get(h_name, "").lower()
        if not actual:
            continue
        if not h_val or h_val in actual:
            info["waf"] = sig["name"]
            break

    # WAF detection via probing: send a deliberately suspicious query.
    if info["waf"] == "Not detected":
        probe_url = target_url + ("&" if "?" in target_url else "?") + "test=<script>alert(1)</script>"
        probe = client.get(probe_url)
        if probe is not None and probe.status_code in {403, 406, 429, 501}:
            # Generic WAF block code detected.
            server_hdr = probe.headers.get("Server", "")
            info["waf"] = f"Generic WAF (HTTP {probe.status_code} from {server_hdr or 'unknown'})"

    logger.info(
        f"Fingerprint -> server: {info['server']}, tech: {info['technology']}, waf: {info['waf']}"
    )
    return info
