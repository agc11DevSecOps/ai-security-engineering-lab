"""Normalized security finding independent of the producing tool."""

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class Finding:
    """A tool finding before downstream consolidation and trust calibration."""

    source: str
    file_path: str
    line: int | None
    severity: str
    rule_id: str
    description: str
    confidence: float | None = None
    cwe: str | None = None
    poc: str | None = None
    extra: Mapping[str, object] = field(default_factory=dict)
