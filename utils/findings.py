"""Common dataclasses for representing scanner findings.

Keeping the schema in one place means new modules can plug into the
reporter without modifying it. Severity strings are uppercase to match
how they are rendered in reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List


SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Approximate CVSS v3.1 scores for default classes of findings. These are
# deliberately conservative; per-finding values can be overridden.
DEFAULT_CVSS = {
    "CRITICAL": 9.8,
    "HIGH": 7.5,
    "MEDIUM": 5.4,
    "LOW": 3.1,
    "INFO": 0.0,
}


@dataclass
class Finding:
    module: str          # Which scanner produced the finding (sqli, xss, ...)
    name: str            # Short title shown in the report
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    url: str             # Affected URL
    description: str     # What the issue is
    evidence: str = ""   # Concrete evidence (response snippet, header, etc.)
    payload: str = ""    # Payload used to demonstrate the issue
    parameter: str = ""  # Vulnerable parameter, if any
    method: str = "GET"  # HTTP method used to trigger
    remediation: str = ""  # Suggested fix
    cvss: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    )

    def __post_init__(self) -> None:
        sev = (self.severity or "INFO").upper()
        if sev not in SEVERITY_LEVELS:
            sev = "INFO"
        self.severity = sev
        if not self.cvss:
            self.cvss = DEFAULT_CVSS.get(sev, 0.0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    """Carries shared state down into every scanner module."""

    target_url: str
    started_at: str
    finished_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def severity_counts(self) -> Dict[str, int]:
        counts = {level: 0 for level in SEVERITY_LEVELS}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
