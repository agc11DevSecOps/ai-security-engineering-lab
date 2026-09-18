"""Common security-finding schema independent of the source tool.

Bandit, Vulnhuntr, and future scanners translate native output to this class
before consolidation. The consolidator never needs to parse tool-specific data.
"""
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    source: str              # "bandit", "vulnhuntr", and similar sources
    file_path: str           # Always relative to the scanned target root
    line: int | None         # None when the scanner does not provide a line
    severity: str            # Normalized to LOW, MEDIUM, HIGH, or CRITICAL
    rule_id: str             # Native tool ID, such as B608 or SQLI
    description: str
    confidence: float | None = None   # 0-1 when provided by the scanner
    cwe: str | None = None
    poc: str | None = None
    extra: dict = field(default_factory=dict)  # Source-specific data

    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    def severity_rank(self) -> int:
        return self.SEVERITY_ORDER.get(self.severity.upper(), 0)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "file_path": self.file_path,
            "line": self.line,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "description": self.description,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "poc": self.poc,
            "extra": self.extra,
        }
