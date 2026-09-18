from __future__ import annotations

import sys
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from core.consolidator import ConsolidationStatus, ConsolidatedFinding  # noqa: E402
from core.finding import Finding  # noqa: E402
from core.trust_score import TrustCalibration, score_finding  # noqa: E402


def consolidated(*, sources: tuple[str, ...], categories: tuple[str, ...]) -> ConsolidatedFinding:
    findings = tuple(
        Finding(
            source=source,
            file_path="db/repository.py",
            line=8,
            severity="MEDIUM",
            rule_id="B608" if category == "SQLI" else "B602",
            description="fixture finding",
        )
        for source, category in zip(sources, categories)
    )
    return ConsolidatedFinding(
        file_path="db/repository.py",
        line=8,
        status=ConsolidationStatus.AGREEMENT,
        findings=findings,
        sources=sources,
        categories=categories,
    )


class TrustScoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calibration = TrustCalibration()

    def test_scores_calibrated_source_category_as_advisory(self) -> None:
        result = score_finding(consolidated(sources=("bandit",), categories=("SQLI",)), self.calibration)

        self.assertEqual(result.status, "calibrated-advisory")
        self.assertEqual(result.score, 0.8)
        self.assertEqual(result.calibration_release, "trust-score-hybrid-v2")

    def test_unavailable_for_unsupported_category(self) -> None:
        result = score_finding(consolidated(sources=("bandit",), categories=("RCE",)), self.calibration)

        self.assertEqual(result.status, "calibration-unavailable")
        self.assertEqual(result.reason, "no-calibrated-source-category")
        self.assertIsNone(result.score)

    def test_independent_agreement_raises_advisory_score(self) -> None:
        result = score_finding(
            consolidated(sources=("bandit", "semgrep"), categories=("SQLI",)),
            self.calibration,
        )

        self.assertEqual(result.status, "calibrated-advisory")
        self.assertEqual(result.score, 1.0)
        self.assertEqual(result.source_profiles, ("bandit:SQLI", "semgrep:SQLI"))

    def test_disagreement_never_receives_a_score(self) -> None:
        result = score_finding(
            consolidated(sources=("bandit", "semgrep"), categories=("SQLI", "RCE")),
            self.calibration,
        )

        self.assertEqual(result.status, "calibration-unavailable")
        self.assertEqual(result.reason, "category-disagreement")
        self.assertIsNone(result.score)


if __name__ == "__main__":
    unittest.main()
