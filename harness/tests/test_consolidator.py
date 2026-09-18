from __future__ import annotations

import sys
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from core.consolidator import ConsolidationStatus, consolidate  # noqa: E402
from core.finding import Finding  # noqa: E402


def finding(
    source: str,
    rule_id: str,
    *,
    file_path: str = "db/repository.py",
    line: int | None = 17,
) -> Finding:
    return Finding(
        source=source,
        file_path=file_path,
        line=line,
        severity="MEDIUM",
        rule_id=rule_id,
        description=f"{rule_id} finding",
    )


class ConsolidatorTests(unittest.TestCase):
    def test_reports_agreement_for_two_sources_with_equivalent_categories(self) -> None:
        bandit = finding("bandit", "B608")
        context_scanner = finding("context-scanner", "sqli")

        results = consolidate((bandit, context_scanner))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ConsolidationStatus.AGREEMENT)
        self.assertEqual(results[0].categories, ("SQLI",))
        self.assertEqual(results[0].sources, ("bandit", "context-scanner"))
        self.assertEqual(results[0].findings, (bandit, context_scanner))
        self.assertFalse(hasattr(results[0], "trust_score"))

    def test_reports_disagreement_without_discarding_either_source(self) -> None:
        bandit = finding("bandit", "B608")
        context_scanner = finding("context-scanner", "RCE")

        results = consolidate((bandit, context_scanner))

        self.assertEqual(results[0].status, ConsolidationStatus.DISAGREEMENT)
        self.assertEqual(results[0].categories, ("SQLI", "RCE"))
        self.assertEqual(results[0].findings, (bandit, context_scanner))

    def test_keeps_multiple_findings_from_one_source_uncorroborated(self) -> None:
        first = finding("bandit", "B608")
        second = finding("bandit", "B602")

        results = consolidate((first, second))

        self.assertEqual(results[0].status, ConsolidationStatus.UNCORROBORATED)
        self.assertEqual(results[0].findings, (first, second))

    def test_does_not_group_findings_at_different_lines(self) -> None:
        line_seventeen = finding("bandit", "B608", line=17)
        line_eighteen = finding("context-scanner", "SQLI", line=18)

        results = consolidate((line_seventeen, line_eighteen))

        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(result.status is ConsolidationStatus.UNCORROBORATED for result in results)
        )

    def test_normalizes_unknown_rule_ids_without_guessing_from_descriptions(self) -> None:
        first = finding("scanner-a", "custom_rule")
        second = finding("scanner-b", "CUSTOM_RULE")

        results = consolidate((first, second))

        self.assertEqual(results[0].status, ConsolidationStatus.AGREEMENT)
        self.assertEqual(results[0].categories, ("CUSTOM_RULE",))

    def test_rejects_non_finding_input(self) -> None:
        with self.assertRaises(TypeError):
            consolidate((object(),))


if __name__ == "__main__":
    unittest.main()
