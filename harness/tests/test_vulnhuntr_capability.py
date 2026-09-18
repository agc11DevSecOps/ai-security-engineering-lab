from __future__ import annotations

import json
import math

# Test fixtures model the external process boundary.
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from core.capability import (  # noqa: E402
    CapabilityRequest,
    CapabilityStatus,
    ErrorCode,
    TaskType,
)
from core.consolidator import ConsolidationStatus, consolidate  # noqa: E402
from core.router import Router  # noqa: E402
from capabilities.bandit_capability import BanditCapability  # noqa: E402


class FakeRunner:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object):
        self.calls.append((command, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeBanditRunner:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __call__(self, command: list[str], **kwargs: object):
        return subprocess.CompletedProcess(
            args=command, returncode=1, stdout=json.dumps(self.payload), stderr=""
        )


class FakeVulnhuntrRunner:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object):
        self.calls.append((command, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        if isinstance(self.response, int):
            return subprocess.CompletedProcess(
                args=command, returncode=self.response, stdout="", stderr=""
            )
        index = command.index("--json")
        Path(command[index + 1]).write_text(
            json.dumps(self.response), encoding="utf-8"
        )
        return subprocess.CompletedProcess(
            args=command, returncode=0, stdout="", stderr=""
        )


class VulnhuntrCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.target = self.workspace / "target"
        self.target.mkdir()
        self.routes = self.target / "routes"
        self.routes.mkdir()
        (self.routes / "api.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self) -> CapabilityRequest:
        return CapabilityRequest(
            task_type=TaskType.CODE_ANALYSIS,
            target=self.target,
            workspace_root=self.workspace,
            timeout_seconds=23,
        )

    def valid_payload(self, file_path: str | None = None) -> dict[str, object]:
        return {
            "findings": [
                {
                    "rule_id": "SQLI",
                    "title": "SQLI in api.py",
                    "severity": "high",
                    "confidence_score": 8,
                    "file_path": file_path or str(self.routes / "api.py"),
                    "description": "potential sql injection",
                    "analysis": "user input flows into a raw query",
                    "poc": "GET /api?x=1' OR 1=1--",
                    "cwe_id": "CWE-89",
                    "cwe_name": "SQL Injection",
                    "context_code": "query = f\"SELECT * FROM t WHERE id={x}\"",
                    "location": {"start_line": 12, "end_line": 14},
                }
            ]
        }


from capabilities.vulnhuntr_capability import VulnhuntrCapability  # noqa: E402


class VulnhuntrNormalizationTests(VulnhuntrCapabilityTests):
    def test_run_normalizes_valid_vulnhuntr_json_without_source_context(self) -> None:
        runner = FakeVulnhuntrRunner(self.valid_payload())

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        finding = result.findings[0]
        self.assertEqual(finding.source, "vulnhuntr")
        self.assertEqual(finding.file_path, "routes/api.py")
        self.assertEqual(finding.line, 12)
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.confidence, 0.8)
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.rule_id, "SQLI")
        self.assertEqual(finding.description, "user input flows into a raw query")
        self.assertEqual(finding.poc, "GET /api?x=1' OR 1=1--")
        self.assertNotIn("context_code", finding.extra)
        self.assertNotIn("SELECT", str(finding))
        command, kwargs = runner.calls[0]
        self.assertIn("-l", command)
        self.assertIn("ollama", command)
        self.assertIn("-r", command)
        self.assertEqual(command[command.index("-a") + 1], str(self.routes / "api.py"))
        self.assertIn("--no-checkpoint", command)
        self.assertEqual(kwargs["timeout"], 23)
        self.assertEqual(kwargs["cwd"], str(self.target))
        self.assertFalse(kwargs["check"])

    def test_run_sets_line_none_when_no_location(self) -> None:
        payload = self.valid_payload()
        del payload["findings"][0]["location"]
        runner = FakeVulnhuntrRunner(payload)

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertIsNone(result.findings[0].line)

    def test_run_returns_completed_with_no_findings_when_output_empty(self) -> None:
        runner = FakeVulnhuntrRunner({"findings": []})

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.findings, ())

    def test_run_returns_incomplete_for_malformed_json(self) -> None:
        class _BadRunner:
            def __call__(self, command, **kwargs):
                Path(command[command.index("--json") + 1]).write_text(
                    "not-json", encoding="utf-8"
                )
                return subprocess.CompletedProcess(
                    args=command, returncode=0, stdout="", stderr=""
                )

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=_BadRunner()).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.MALFORMED_TOOL_OUTPUT)

    def test_run_returns_incomplete_when_binary_unavailable(self) -> None:
        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=FakeVulnhuntrRunner(FileNotFoundError())).run(
            self.request()
        )

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)

    def test_run_returns_incomplete_on_timeout(self) -> None:
        result = VulnhuntrCapability(
            vulnhuntr_bin="vulnhuntr-test",
            runner=FakeVulnhuntrRunner(subprocess.TimeoutExpired(cmd="vulnhuntr", timeout=23))
        ).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_TIMEOUT)

    def test_run_returns_incomplete_on_unexpected_exit_code(self) -> None:
        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=FakeVulnhuntrRunner(2)).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_FAILED)

    def test_run_preserves_valid_findings_before_a_later_file_fails(self) -> None:
        database = self.target / "db"
        database.mkdir()
        repository = database / "repository.py"
        repository.write_text("x = 1\n", encoding="utf-8")

        class _PartialRunner:
            def __init__(self, payload: dict[str, object]) -> None:
                self.payload = payload
                self.calls = 0

            def __call__(self, command, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    Path(command[command.index("--json") + 1]).write_text(
                        json.dumps(self.payload), encoding="utf-8"
                    )
                    return subprocess.CompletedProcess(
                        args=command, returncode=0, stdout="", stderr=""
                    )
                return subprocess.CompletedProcess(
                    args=command, returncode=2, stdout="", stderr=""
                )

        payload = self.valid_payload(str(repository))
        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=_PartialRunner(payload)).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_FAILED)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].file_path, "db/repository.py")

    def test_run_rejects_report_outside_target(self) -> None:
        outside = Path(self.temp_dir.name) / "elsewhere.py"
        outside.write_text("x = 1\n", encoding="utf-8")
        runner = FakeVulnhuntrRunner(self.valid_payload(str(outside)))

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.UNSAFE_TOOL_OUTPUT)

    def test_run_does_not_discover_files_in_excluded_directories(self) -> None:
        excluded = self.target / "node_modules"
        excluded.mkdir()
        (excluded / "bad.py").write_text("eval('bad')\n", encoding="utf-8")
        runner = FakeVulnhuntrRunner({"findings": []})

        result = VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        analyzed = [call[0][call[0].index("-a") + 1] for call in runner.calls]
        self.assertNotIn(str(excluded / "bad.py"), analyzed)
        self.assertIn(str(self.routes / "api.py"), analyzed)

    def test_run_rejects_invalid_confidence_scores(self) -> None:
        for value in (-1, 11, True, "8", math.inf, math.nan):
            payload = self.valid_payload()
            payload["findings"][0]["confidence_score"] = value
            with self.subTest(value=repr(value)):
                result = VulnhuntrCapability(
                    vulnhuntr_bin="vulnhuntr-test",
                    runner=FakeVulnhuntrRunner(payload)
                ).run(self.request())
                self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
                self.assertEqual(result.error_code, ErrorCode.MALFORMED_TOOL_OUTPUT)


class BanditVulnhuntrConsolidationTests(VulnhuntrCapabilityTests):
    def _bandit_payload(self) -> dict[str, object]:
        return {
            "results": [
                {
                    "filename": "db/repository.py",
                    "line_number": 17,
                    "issue_severity": "MEDIUM",
                    "test_id": "B608",
                    "issue_text": "Possible SQL injection.",
                    "issue_confidence": "HIGH",
                    "issue_cwe": {"id": 89},
                    "test_name": "hardcoded_sql_expressions",
                    "more_info": "https://bandit.example/B608",
                }
            ]
        }

    def _vulnhuntr_payload(self, rule_id: str) -> dict[str, object]:
        db = self.target / "db"
        db.mkdir()
        (db / "repository.py").write_text("x = 1\n", encoding="utf-8")
        return {
            "findings": [
                {
                    "rule_id": rule_id,
                    "severity": "medium",
                    "confidence_score": 7,
                    "file_path": str(db / "repository.py"),
                    "description": "finding",
                    "location": {"start_line": 17},
                }
            ]
        }

    def test_agreement_when_bandit_and_vulnhuntr_share_line_and_category(self) -> None:
        router = Router(
            (
                BanditCapability(runner=FakeBanditRunner(self._bandit_payload())),
                VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=FakeVulnhuntrRunner(self._vulnhuntr_payload("SQLI"))),
            )
        )

        results = router.run(self.request())
        consolidated = consolidate(f for r in results for f in r.findings)

        self.assertEqual(len(consolidated), 1)
        self.assertEqual(consolidated[0].status, ConsolidationStatus.AGREEMENT)
        self.assertEqual(consolidated[0].categories, ("SQLI",))
        self.assertEqual(consolidated[0].sources, ("bandit", "vulnhuntr"))

    def test_disagreement_when_same_line_reports_different_categories(self) -> None:
        router = Router(
            (
                BanditCapability(runner=FakeBanditRunner(self._bandit_payload())),
                VulnhuntrCapability(vulnhuntr_bin="vulnhuntr-test", runner=FakeVulnhuntrRunner(self._vulnhuntr_payload("RCE"))),
            )
        )

        results = router.run(self.request())
        consolidated = consolidate(f for r in results for f in r.findings)

        self.assertEqual(consolidated[0].status, ConsolidationStatus.DISAGREEMENT)
        self.assertEqual(consolidated[0].categories, ("SQLI", "RCE"))


if __name__ == "__main__":
    unittest.main()
