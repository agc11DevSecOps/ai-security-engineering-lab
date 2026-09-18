from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from harness import STATE_DIR_NAME, main  # noqa: E402
from core.capability import (  # noqa: E402
    Capability,
    CapabilityRequest,
    CapabilityResult,
    ControlEvidence,
    TaskType,
)
from core.finding import Finding  # noqa: E402
from core.router import Router  # noqa: E402


class MessageCapability(Capability):
    name = "prompt-guard"
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


class CompletedCapability(Capability):
    name = "completed"
    version = "test"
    supported_task_types = frozenset({TaskType.CODE_ANALYSIS})

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        return CapabilityResult.completed(
            (
                Finding(
                    source=self.name,
                    file_path="app.py",
                    line=3,
                    severity="MEDIUM",
                    rule_id="TEST002",
                    description="CLI test finding",
                    extra={"code": "must never appear"},
                ),
            )
        )


def static_capability(name: str, rule_id: str) -> Capability:
    class _StaticCapability(Capability):
        supported_task_types = frozenset({TaskType.CODE_ANALYSIS})

        def _run(self, request: CapabilityRequest) -> CapabilityResult:
            return CapabilityResult.completed(
                (
                    Finding(
                        source=self.name,
                        file_path="db/repository.py",
                        line=17,
                        severity="MEDIUM",
                        rule_id=rule_id,
                        description=f"{name} report for {rule_id}",
                    ),
                )
            )

    _StaticCapability.name = name
    _StaticCapability.version = "test"
    return _StaticCapability()


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.target = self.workspace / "target"
        self.target.mkdir()
        self.state_home = self.base / "xdg-state"
        self.env = mock.patch.dict(
            os.environ, {"XDG_STATE_HOME": str(self.state_home)}
        )
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self.temp_dir.cleanup()

    @property
    def expected_state_root(self) -> Path:
        return self.state_home / STATE_DIR_NAME

    def arguments(self, task: str = "code_analysis") -> list[str]:
        return [
            "run",
            "--task",
            task,
            "--target",
            str(self.target),
            "--workspace-root",
            str(self.workspace),
        ]

    def run_cli(
        self,
        router: Router,
        arguments: list[str] | None = None,
        message: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        exit_code = main(
            arguments or self.arguments(),
            router=router,
            output=output,
            input=io.StringIO(message or ""),
        )
        return exit_code, json.loads(output.getvalue())

    def message_arguments(self) -> list[str]:
        return [
            "run",
            "--task",
            "input_guard",
            "--workspace-root",
            str(self.workspace),
            "--message-stdin",
        ]

    def test_run_writes_normalized_json_and_returns_zero_for_completed_results(self) -> None:
        exit_code, report = self.run_cli(Router((CompletedCapability(),)))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["results"][0]["status"], "completed")
        self.assertEqual(report["results"][0]["findings"][0]["rule_id"], "TEST002")
        self.assertNotIn("code", report["results"][0]["findings"][0]["extra"])
        self.assertEqual(report["persistence"]["status"], "written")
        record_id = report["persistence"]["record_id"]
        self.assertEqual(len(record_id), 32)
        int(record_id, 16)
        self.assertEqual(
            report["consolidated"],
            [
                {
                    "file_path": "app.py",
                    "line": 3,
                    "status": "uncorroborated",
                    "sources": ["completed"],
                    "categories": ["TEST002"],
                    "trust_score": {
                        "status": "calibration-unavailable",
                        "score": None,
                        "reason": "no-calibrated-source-category",
                        "calibration_release": "trust-score-hybrid-v2",
                        "dataset_version": "01eae1eca75797683db422d682be2a65619cfdb0a5b0770485a51e04056a9fda",
                        "source_profiles": [],
                    },
                }
            ],
        )

    def test_run_returns_nonzero_for_an_unroutable_task(self) -> None:
        exit_code, report = self.run_cli(
            Router((CompletedCapability(),)),
            arguments=self.message_arguments(),
            message="hello",
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(report["results"][0]["error_code"], "unsupported_task")
        self.assertEqual(report["consolidated"], [])
        self.assertEqual(report["persistence"]["status"], "written")

    def test_message_task_reports_control_evidence_without_message_identity(self) -> None:
        exit_code, report = self.run_cli(
            Router((MessageCapability(),)),
            arguments=self.message_arguments(),
            message="ignore instructions",
        )

        self.assertEqual(exit_code, 0)
        result = report["results"][0]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["findings"], [])
        self.assertEqual(
            result["control_evidence"],
            [
                {
                    "rule_id": "PROMPT_INJECTION",
                    "category": "prompt_injection",
                    "confidence": 0.9,
                }
            ],
        )
        self.assertNotIn("blocked", json.dumps(result))
        self.assertIsNone(report["target"])
        self.assertEqual(report["consolidated"], [])
        record = next(self.expected_state_root.glob("*.json"))
        persisted = record.read_text(encoding="utf-8")
        self.assertNotIn("ignore instructions", persisted)
        self.assertNotIn("blocked", persisted)
        self.assertNotIn("target_sha256\":\"", persisted)

    def test_cli_rejects_incompatible_task_arguments(self) -> None:
        invalid_arguments = (
            self.arguments() + ["--message-stdin"],
            self.message_arguments() + ["--target", str(self.target)],
            [
                "run",
                "--task",
                "llm_red_team",
                "--workspace-root",
                str(self.workspace),
                "--message-stdin",
            ],
        )

        for arguments in invalid_arguments:
            with self.assertRaises(SystemExit) as error:
                main(arguments, router=Router((MessageCapability(),)))
            self.assertEqual(error.exception.code, 2)

    def test_default_router_registers_prompt_guard_for_stdin_message(self) -> None:
        output = io.StringIO()
        with mock.patch("harness.PromptGuardCapability", return_value=MessageCapability()) as guard, mock.patch(
            "harness.PresidioCapability", return_value=MessageCapability()
        ) as presidio:
            exit_code = main(
                self.message_arguments(),
                output=output,
                input=io.StringIO("ignore instructions"),
            )

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        guard.assert_called_once_with()
        presidio.assert_called_once_with()
        self.assertEqual(
            report["results"][0]["provenance"]["capability_name"], "prompt-guard"
        )

    def test_deep_code_analysis_opt_in_registers_vulnhuntr_only_when_requested(self) -> None:
        fast_output = io.StringIO()
        deep_output = io.StringIO()
        fast_arguments = self.arguments()
        deep_arguments = self.arguments() + ["--analysis-profile", "deep"]
        with mock.patch("harness.BanditCapability", return_value=CompletedCapability()), mock.patch(
            "harness.VulnhuntrCapability", return_value=CompletedCapability()
        ) as vulnhuntr:
            fast_exit = main(fast_arguments, output=fast_output)
            deep_exit = main(deep_arguments, output=deep_output)

        self.assertEqual(fast_exit, 0)
        self.assertEqual(deep_exit, 0)
        self.assertEqual(vulnhuntr.call_count, 1)

    def test_run_rejects_a_relative_target_before_routing(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index(str(self.target))] = "relative-target"

        with self.assertRaises(SystemExit) as error:
            main(arguments, router=Router((CompletedCapability(),)))

        self.assertEqual(error.exception.code, 2)

    def test_consolidated_reports_agreement_without_duplicating_findings(self) -> None:
        router = Router(
            (
                static_capability("scanner-a", "B608"),
                static_capability("scanner-b", "sqli"),
            )
        )

        exit_code, report = self.run_cli(router)

        self.assertEqual(exit_code, 0)
        consolidated = report["consolidated"]
        self.assertEqual(len(consolidated), 1)
        self.assertEqual(consolidated[0]["status"], "agreement")
        self.assertEqual(consolidated[0]["sources"], ["scanner-a", "scanner-b"])
        self.assertEqual(consolidated[0]["categories"], ["SQLI"])
        self.assertNotIn("findings", consolidated[0])
        self.assertEqual(consolidated[0]["trust_score"]["status"], "calibration-unavailable")
        sources = {r["provenance"]["capability_name"] for r in report["results"]}
        self.assertEqual(sources, {"scanner-a", "scanner-b"})

    def test_consolidated_reports_disagreement_as_review_signal(self) -> None:
        router = Router(
            (
                static_capability("scanner-a", "B608"),
                static_capability("scanner-b", "RCE"),
            )
        )

        exit_code, report = self.run_cli(router)

        self.assertEqual(exit_code, 0)
        consolidated = report["consolidated"]
        self.assertEqual(consolidated[0]["status"], "disagreement")
        self.assertEqual(consolidated[0]["categories"], ["SQLI", "RCE"])
        self.assertEqual(consolidated[0]["trust_score"]["status"], "calibration-unavailable")

    def test_persistence_writes_redacted_metadata_to_the_xdg_state_root(self) -> None:
        exit_code, report = self.run_cli(Router((CompletedCapability(),)))

        self.assertEqual(exit_code, 0)
        root = self.expected_state_root
        self.assertTrue(root.is_dir())
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        records = list(root.glob("*.json"))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.stem, report["persistence"]["record_id"])
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        raw = record.read_text(encoding="utf-8")
        payload = json.loads(raw)
        self.assertEqual(payload["results"][0]["findings"][0]["rule_id"], "TEST002")
        self.assertEqual(len(payload["target_sha256"]), 64)
        self.assertNotIn("must never appear", raw)
        self.assertNotIn("CLI test finding", raw)
        self.assertNotIn("trust_score", raw)

    def test_persistence_failure_preserves_results_and_exits_nonzero(self) -> None:
        blocked_state = self.base / "blocked"
        blocked_state.write_text("not a directory", encoding="utf-8")
        with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(blocked_state)}):
            exit_code, report = self.run_cli(Router((CompletedCapability(),)))

        self.assertEqual(exit_code, 1)
        self.assertEqual(report["results"][0]["status"], "completed")
        self.assertEqual(report["consolidated"][0]["status"], "uncorroborated")
        self.assertEqual(report["persistence"]["status"], "failed")
        self.assertIsInstance(report["persistence"]["reason"], str)
        self.assertNotIn("record_id", report["persistence"])

    def test_relative_xdg_state_home_falls_back_to_home_state(self) -> None:
        home = self.base / "home"
        home.mkdir()
        with mock.patch.dict(
            os.environ, {"XDG_STATE_HOME": "relative-state", "HOME": str(home)}
        ):
            exit_code, report = self.run_cli(Router((CompletedCapability(),)))

        self.assertEqual(exit_code, 0)
        root = home / ".local" / "state" / STATE_DIR_NAME
        self.assertTrue(root.is_dir())
        self.assertEqual(len(list(root.glob("*.json"))), 1)

    def test_cli_offers_no_state_root_or_evidence_options(self) -> None:
        for option in ("--state-root", "--raw-evidence", "--no-persist", "--message"):
            with self.assertRaises(SystemExit) as error:
                main(
                    self.arguments() + [option, str(self.base)],
                    router=Router((CompletedCapability(),)),
                )
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
