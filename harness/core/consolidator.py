"""Preserve and classify corroborating findings from independent sources."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from core.finding import Finding


CATEGORY_EQUIVALENCE = {
    "B105": "HARDCODED_SECRET",
    "B301": "RCE",
    "B307": "RCE",
    "B324": "CRYPTO_WEAK",
    "B602": "RCE",
    "B608": "SQLI",
}


class ConsolidationStatus(str, Enum):
    AGREEMENT = "agreement"
    DISAGREEMENT = "disagreement"
    UNCORROBORATED = "uncorroborated"


@dataclass(frozen=True)
class ConsolidatedFinding:
    """Evidence retained at one exact source location, with no trust score."""

    file_path: str
    line: int | None
    status: ConsolidationStatus
    findings: tuple[Finding, ...]
    sources: tuple[str, ...]
    categories: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.file_path, str) or not self.file_path:
            raise TypeError("file_path must be a non-empty string")
        if self.line is not None and (
            not isinstance(self.line, int) or isinstance(self.line, bool) or self.line < 1
        ):
            raise TypeError("line must be a positive integer or None")
        if not isinstance(self.status, ConsolidationStatus):
            raise TypeError("status must be a ConsolidationStatus")
        if (
            not isinstance(self.findings, tuple)
            or not self.findings
            or not all(isinstance(finding, Finding) for finding in self.findings)
        ):
            raise TypeError("findings must be a non-empty tuple of Finding instances")
        if (
            not isinstance(self.sources, tuple)
            or not self.sources
            or not all(isinstance(source, str) and source for source in self.sources)
        ):
            raise TypeError("sources must be non-empty strings")
        if (
            not isinstance(self.categories, tuple)
            or not self.categories
            or not all(isinstance(category, str) and category for category in self.categories)
        ):
            raise TypeError("categories must be non-empty strings")


def consolidate(findings: Iterable[Finding]) -> tuple[ConsolidatedFinding, ...]:
    """Group exact locations and retain all source evidence in input order."""
    grouped: dict[tuple[str, int | None], list[Finding]] = {}
    for finding in findings:
        if not isinstance(finding, Finding):
            raise TypeError("findings must contain only Finding instances")
        grouped.setdefault((finding.file_path, finding.line), []).append(finding)

    return tuple(
        _consolidated_finding(file_path, line, group)
        for (file_path, line), group in grouped.items()
    )


def _consolidated_finding(
    file_path: str, line: int | None, findings: list[Finding]
) -> ConsolidatedFinding:
    sources = _distinct_in_order(finding.source for finding in findings)
    categories = _distinct_in_order(_category(finding) for finding in findings)
    if len(sources) < 2:
        status = ConsolidationStatus.UNCORROBORATED
    elif len(categories) == 1:
        status = ConsolidationStatus.AGREEMENT
    else:
        status = ConsolidationStatus.DISAGREEMENT
    return ConsolidatedFinding(
        file_path=file_path,
        line=line,
        status=status,
        findings=tuple(findings),
        sources=sources,
        categories=categories,
    )


def _category(finding: Finding) -> str:
    rule_id = finding.rule_id.upper()
    return CATEGORY_EQUIVALENCE.get(rule_id, rule_id)


def _distinct_in_order(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
