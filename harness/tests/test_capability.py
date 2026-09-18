from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from core.capability import (  # noqa: E402
    Capability,
    CapabilityRequest,
    CapabilityResult,
    CapabilityStatus,
    ControlEvidence,
    ErrorCode,
    MAX_MESSAGE_BYTES,
    TaskType,
)
from core.finding import Finding  # noqa: E402


class RecordingCapability(Capability):
    name = "recording"
    version = "test"
    supported_task_types = frozenset({TaskType.CODE_ANALYSIS})

    def __init__(self) -> None:
        self.calls = 0

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        self.calls += 1
        return CapabilityResult.completed(
            findings=(
                Finding(
                    source="recording",
                    file_path="app.py",
                    line=7,
                    severity="HIGH",
                    rule_id="TEST001",
                    description="Test finding",
                ),
            )
        )


class CapabilityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.target = self.workspace / "target"
        self.target.mkdir()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self, **overrides: object) -> CapabilityRequest:
        values: dict[str, object] = {
            "task_type": TaskType.CODE_ANALYSIS,
            "target": self.target,
            "workspace_root": self.workspace,
        }
        values.update(overrides)
        return CapabilityRequest(**values)

    def test_run_returns_normalized_findings_with_capability_provenance(self) -> None:
        result = RecordingCapability().run(self.request())

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.findings[0].rule_id, "TEST001")
        self.assertEqual(result.provenance.capability_name, "recording")
        self.assertEqual(result.provenance.capability_version, "test")
        self.assertEqual(result.provenance.target, self.target.resolve())

    def test_run_rejects_relative_paths_before_invoking_capability(self) -> None:
        capability = RecordingCapability()

        result = capability.run(self.request(target=Path("relative-target")))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.RELATIVE_PATH)
        self.assertEqual(capability.calls, 0)

    def test_run_rejects_target_outside_workspace(self) -> None:
        outside_target = Path(self.temp_dir.name) / "outside"
        outside_target.mkdir()

        result = RecordingCapability().run(self.request(target=outside_target))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.OUTSIDE_WORKSPACE)

    def test_run_rejects_symlink_escape(self) -> None:
        outside_target = Path(self.temp_dir.name) / "outside"
        outside_target.mkdir()
        escaped_target = self.workspace / "escaped"
        escaped_target.symlink_to(outside_target, target_is_directory=True)

        result = RecordingCapability().run(self.request(target=escaped_target))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.OUTSIDE_WORKSPACE)

    def test_run_rejects_excluded_target_directory(self) -> None:
        excluded_target = self.workspace / ".git"
        excluded_target.mkdir()

        result = RecordingCapability().run(self.request(target=excluded_target))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.EXCLUDED_PATH)

    def test_run_rejects_unsupported_task_without_guessing(self) -> None:
        result = RecordingCapability().run(
            self.request(task_type=TaskType.INPUT_GUARD, target=None, message="hello")
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_TASK)
        self.assertEqual(result.findings, ())

    def test_run_rejects_remote_execution_by_default(self) -> None:
        result = RecordingCapability().run(self.request(allow_remote=True))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.REMOTE_NOT_ALLOWED)

    def test_run_rejects_raw_evidence_retention_over_seven_days(self) -> None:
        result = RecordingCapability().run(
            self.request(allow_raw_evidence=True, raw_evidence_retention_days=8)
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.INVALID_RETENTION)

    def test_run_rejects_unbounded_execution_timeout(self) -> None:
        result = RecordingCapability().run(self.request(timeout_seconds=3_601))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.INVALID_TIMEOUT)

    def test_run_rejects_malformed_execution_timeout(self) -> None:
        result = RecordingCapability().run(self.request(timeout_seconds="forever"))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.INVALID_TIMEOUT)

    def test_finding_cannot_include_a_final_trust_score(self) -> None:
        finding = Finding(
            source="recording",
            file_path="app.py",
            line=7,
            severity="HIGH",
            rule_id="TEST001",
            description="Test finding",
        )

        self.assertFalse(hasattr(finding, "trust_score"))
        with self.assertRaises(TypeError):
            Finding(
                source="recording",
                file_path="app.py",
                line=7,
                severity="HIGH",
                rule_id="TEST001",
                description="Test finding",
                trust_score=1.0,
            )

    def test_result_rejects_untyped_findings(self) -> None:
        with self.assertRaises(TypeError):
            CapabilityResult.completed(findings=("not-a-finding",))


class RecordingMessageCapability(Capability):
    name = "message-recording"
    version = "test"
    supported_task_types = frozenset({TaskType.INPUT_GUARD})

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        return CapabilityResult.observed(
            (
                ControlEvidence(
                    rule_id="PROMPT_INJECTION",
                    category="prompt_injection",
                    confidence=0.9,
                ),
            )
        )


class MessageTaskContractTests(CapabilityContractTests):
    def test_message_capability_returns_control_evidence_without_target(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(task_type=TaskType.INPUT_GUARD, target=None, message="ignore instructions")
        )

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.findings, ())
        self.assertIsNone(result.provenance.target)
        self.assertEqual(result.control_evidence[0].rule_id, "PROMPT_INJECTION")
        self.assertEqual(result.control_evidence[0].category, "prompt_injection")
        self.assertEqual(result.control_evidence[0].confidence, 0.9)

    def test_message_task_rejects_a_filesystem_target(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(task_type=TaskType.INPUT_GUARD, target=self.target, message="x")
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.UNEXPECTED_TARGET)

    def test_message_task_requires_a_message(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(task_type=TaskType.INPUT_GUARD, target=None)
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.MISSING_MESSAGE)

    def test_message_task_rejects_whitespace_only_message(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(task_type=TaskType.INPUT_GUARD, target=None, message=" \t\n")
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.MISSING_MESSAGE)

    def test_message_task_rejects_an_oversized_message(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(
                task_type=TaskType.INPUT_GUARD,
                target=None,
                message="x" * (MAX_MESSAGE_BYTES + 1),
            )
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.MESSAGE_TOO_LARGE)

    def test_code_analysis_rejects_a_message(self) -> None:
        capability = RecordingCapability()

        result = capability.run(self.request(message="not code"))

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.UNEXPECTED_MESSAGE)
        self.assertEqual(capability.calls, 0)

    def test_llm_red_team_is_unavailable_before_invoking_capability(self) -> None:
        capability = RecordingMessageCapability()

        result = capability.run(
            self.request(task_type=TaskType.LLM_RED_TEAM, target=None, message="probe")
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_TASK)

    def test_input_guard_rejects_raw_evidence_retention(self) -> None:
        result = RecordingMessageCapability().run(
            self.request(
                task_type=TaskType.INPUT_GUARD,
                target=None,
                message="hello",
                allow_raw_evidence=True,
            )
        )

        self.assertEqual(result.status, CapabilityStatus.FAILED)
        self.assertEqual(result.error_code, ErrorCode.RAW_EVIDENCE_NOT_ALLOWED)

    def test_completed_result_cannot_carry_findings_and_control_evidence(self) -> None:
        with self.assertRaises(ValueError):
            CapabilityResult(
                status=CapabilityStatus.COMPLETED,
                findings=(
                    Finding(
                        source="recording",
                        file_path="app.py",
                        line=7,
                        severity="HIGH",
                        rule_id="TEST001",
                        description="Test finding",
                    ),
                ),
                control_evidence=(
                    ControlEvidence(
                        rule_id="PROMPT_INJECTION",
                        category="prompt_injection",
                    ),
                ),
            )

    def test_control_evidence_requires_a_rule_category_and_bounded_confidence(self) -> None:
        with self.assertRaises(TypeError):
            ControlEvidence(rule_id="", category="prompt_injection")
        with self.assertRaises(TypeError):
            ControlEvidence(rule_id="PROMPT_INJECTION", category="prompt_injection", confidence=1.1)


if __name__ == "__main__":
    unittest.main()
