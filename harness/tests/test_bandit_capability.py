from __future__ import annotations

import json

# Test fixtures model the external process boundary.
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from capabilities.bandit_capability import BanditCapability  # noqa: E402
from core.capability import (  # noqa: E402
    CapabilityRequest,
    CapabilityStatus,
    ErrorCode,
    TaskType,
)


class FakeRunner:
    def __init__(self, response: subprocess.CompletedProcess[str] | Exception) -> None:
        self.response = response
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class BanditCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.target = self.workspace / "target"
        self.target.mkdir()
        (self.target / "app.py").write_text("print('safe')\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self) -> CapabilityRequest:
        return CapabilityRequest(
            task_type=TaskType.CODE_ANALYSIS,
            target=self.target,
            workspace_root=self.workspace,
            timeout_seconds=17,
        )

    def completed_process(self, payload: object, returncode: int = 1) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["bandit"],
            returncode=returncode,
            stdout=json.dumps(payload),
            stderr="",
        )

    def valid_payload(self, filename: str = "target/app.py") -> dict[str, object]:
        return {
            "results": [
                {
                    "filename": filename,
                    "line_number": 7,
                    "issue_severity": "MEDIUM",
                    "test_id": "B608",
                    "issue_text": "Possible SQL injection.",
                    "issue_confidence": "LOW",
                    "issue_cwe": {"id": 89},
                    "test_name": "hardcoded_sql_expressions",
                    "more_info": "https://bandit.example/B608",
                    "code": "secret source must not be retained",
                }
            ]
        }

    def test_run_normalizes_valid_bandit_json_without_source_snippet(self) -> None:
        runner = FakeRunner(self.completed_process(self.valid_payload()))

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.findings[0].file_path, "app.py")
        self.assertEqual(result.findings[0].severity, "MEDIUM")
        self.assertEqual(result.findings[0].confidence, 0.33)
        self.assertEqual(result.findings[0].cwe, "CWE-89")
        self.assertNotIn("code", result.findings[0].extra)
        self.assertNotIn("secret source", str(result.findings[0]))
        command, kwargs = runner.calls[0]
        self.assertEqual(command[0], "bandit")
        self.assertIn("-r", command)
        self.assertIn("-x", command)
        self.assertEqual(kwargs["timeout"], 17)
        self.assertFalse(kwargs["check"])

    def test_run_returns_incomplete_for_malformed_json(self) -> None:
        runner = FakeRunner(
            subprocess.CompletedProcess(
                args=["bandit"], returncode=1, stdout="not-json", stderr=""
            )
        )

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.MALFORMED_TOOL_OUTPUT)

    def test_run_returns_incomplete_when_bandit_is_unavailable(self) -> None:
        runner = FakeRunner(FileNotFoundError())

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)

    def test_run_returns_incomplete_when_bandit_times_out(self) -> None:
        runner = FakeRunner(subprocess.TimeoutExpired(cmd="bandit", timeout=17))

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_TIMEOUT)

    def test_run_rejects_unexpected_bandit_exit_code(self) -> None:
        runner = FakeRunner(self.completed_process({"results": []}, returncode=2))

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_FAILED)

    def test_run_rejects_tool_output_outside_target(self) -> None:
        runner = FakeRunner(self.completed_process(self.valid_payload("/etc/passwd")))

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.UNSAFE_TOOL_OUTPUT)

    def test_run_rejects_tool_output_from_excluded_descendant(self) -> None:
        excluded_dir = self.target / "node_modules"
        excluded_dir.mkdir()
        excluded_file = excluded_dir / "bad.py"
        excluded_file.write_text("eval('bad')\n", encoding="utf-8")
        runner = FakeRunner(
            self.completed_process(self.valid_payload("target/node_modules/bad.py"))
        )

        result = BanditCapability(runner=runner).run(self.request())

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.UNSAFE_TOOL_OUTPUT)


if __name__ == "__main__":
    unittest.main()
