from __future__ import annotations

import sys
from unittest import mock
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT / "scripts"))

import measure_harness_value  # noqa: E402
from measure_harness_value import score_profile  # noqa: E402


class HarnessValueMeasurementTests(unittest.TestCase):
    def test_deep_profile_requires_explicit_case_selection(self) -> None:
        oracle = {"cases": {"case-a": {}}}
        with mock.patch.object(measure_harness_value, "_read_json", return_value=oracle):
            with self.assertRaises(SystemExit) as error:
                measure_harness_value.main(["--profile", "deep"])

        self.assertEqual(error.exception.code, 2)

    def test_score_profile_counts_only_exact_category_and_location_matches(self) -> None:
        oracle = {
            "cases": {
                "case-a": {
                    "verdict": "vulnerable",
                    "expected_findings": [
                        {
                            "category": "SQLI",
                            "accepted_detection_locations": [
                                {"path": "db/repository.py", "line": 7}
                            ],
                        }
                    ],
                },
                "case-b": {"verdict": "safe", "expected_findings": []},
                "case-c": {"verdict": "vulnerable", "expected_findings": []},
            }
        }
        runs = [
            {
                "case": "case-a",
                "profile": "fast",
                "status": "completed",
                "findings": [
                    {"rule_id": "B608", "file_path": "db/repository.py", "line": 7}
                ],
            },
            {
                "case": "case-b",
                "profile": "fast",
                "status": "completed",
                "findings": [{"rule_id": "SQLI", "file_path": "db/repository.py", "line": 1}],
            },
            {
                "case": "case-c",
                "profile": "fast",
                "status": "incomplete",
                "findings": [],
            },
        ]

        score = score_profile(runs, oracle, "fast")

        self.assertEqual(score["tp"], 1)
        self.assertEqual(score["fp"], 1)
        self.assertEqual(score["fn"], 0)
        self.assertEqual(score["tn"], 0)
        self.assertEqual(score["unavailable"], 1)
        self.assertEqual(score["precision"], 0.5)
