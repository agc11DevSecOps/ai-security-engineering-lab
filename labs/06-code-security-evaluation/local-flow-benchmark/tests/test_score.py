import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from score import FLOW_PATHS, score_observations
from triage_results import validate


GROUND_TRUTH = {
    "cases": {
        "case-a": {"verdict": "vulnerable", "expected_findings": [{"cwe": "CWE-89"}]},
        "case-b": {"verdict": "safe", "expected_findings": []},
    }
}


def test_score_uses_explicit_verdicts_and_keeps_failed_scans_out_of_false_negatives():
    observations = [
        {"tool": "codeql", "case": "case-a", "status": "success", "result": {"detected": True, "flow_paths": sorted(FLOW_PATHS)}},
        {"tool": "codeql", "case": "case-b", "status": "success", "result": {"detected": True, "flow_paths": []}},
        {"tool": "bandit", "case": "case-a", "status": "failed", "result": None},
        {"tool": "bandit", "case": "case-b", "status": "success", "result": {"detected": False, "flow_paths": []}},
    ]

    result = score_observations(observations, GROUND_TRUTH)

    assert result["codeql"] == {"tp": 1, "fp": 1, "fn": 0, "tn": 0, "unavailable": 0, "flow_evidence": 1, "precision": 0.5, "recall": 1.0, "f1": 2 / 3}
    assert result["bandit"]["unavailable"] == 1
    assert result["bandit"]["fn"] == 0


def test_score_falls_back_to_expected_findings_for_legacy_ground_truth():
    observations = [
        {"tool": "semgrep", "case": "case-a", "status": "success", "result": {"detected": True, "flow_paths": []}},
        {"tool": "semgrep", "case": "case-b", "status": "success", "result": {"detected": False, "flow_paths": []}},
    ]
    legacy_ground_truth = {
        "cases": {
            "case-a": {"expected_findings": [{"cwe": "CWE-89"}]},
            "case-b": {"expected_findings": []},
        }
    }

    result = score_observations(observations, legacy_ground_truth)

    assert result["semgrep"]["tp"] == 1
    assert result["semgrep"]["tn"] == 1


def test_score_rejects_a_detection_outside_the_accepted_location():
    ground_truth = {
        "cases": {
            "case-a": {
                "verdict": "vulnerable",
                "expected_findings": [
                    {"accepted_detection_locations": [{"path": "db/repository.py", "line": 7}]}
                ],
            }
        }
    }
    observations = [
        {"tool": "bandit", "case": "case-a", "status": "success", "result": {"detected": True, "locations": [{"path": "db/repository.py", "line": 99}], "flow_paths": []}}
    ]

    result = score_observations(observations, ground_truth)

    assert result["bandit"]["tp"] == 0
    assert result["bandit"]["fn"] == 1


def test_score_accepts_a_second_cwe_family():
    ground_truth = {
        "cases": {
            "case-i": {
                "verdict": "vulnerable",
                "expected_findings": [{"cwe": "CWE-78", "accepted_detection_locations": [{"path": "db/repository.py", "line": 8}]}],
            },
            "case-j": {"verdict": "safe", "expected_findings": []},
        }
    }
    observations = [
        {"tool": "bandit", "case": "case-i", "status": "success", "result": {"detected": True, "locations": [{"path": "db/repository.py", "line": 8}], "flow_paths": []}},
        {"tool": "bandit", "case": "case-j", "status": "success", "result": {"detected": False, "locations": [], "flow_paths": []}},
    ]

    assert score_observations(observations, ground_truth)["bandit"]["tp"] == 1


def test_triage_validation_rejects_lost_or_deprioritized_findings():
    findings = [{"finding_id": "bandit:B608:7"}]

    assert validate(findings, {"triage": [{"finding_id": "bandit:B608:7", "category": "BLOQUEANTE"}]}) == []
    assert validate(findings, {"triage": [{"finding_id": "bandit:B608:7", "category": "DEUDA_TECNICA"}]})
    assert validate(findings, {"triage": []})
