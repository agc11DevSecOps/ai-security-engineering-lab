from __future__ import annotations

import json
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from capabilities.garak_capability import GarakCapability  # noqa: E402
from core.capability import (  # noqa: E402
    CapabilityRequest,
    CapabilityStatus,
    ErrorCode,
    TaskType,
)
from core.garak_campaign import (  # noqa: E402
    CampaignManifestError,
    GarakReportSummary,
    GarakRunError,
    GarakRunResult,
    load_approved_staging_campaign,
    require_approved_staging_config,
)
from core.evidence_store import EvidenceStore  # noqa: E402
from core.router import Router  # noqa: E402
from harness import main  # noqa: E402


class FakeStagingRunner:
    def __init__(self, outcome: GarakRunResult) -> None:
        self.outcome = outcome
        self.manifests: list[Path] = []

    def run(self, manifest_path: Path) -> GarakRunResult:
        self.manifests.append(Path(manifest_path))
        return self.outcome


class GarakCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.manifest = PHASE_ROOT / "campaigns" / "garak-synthetic-staging-template.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self, manifest: Path | None = None) -> CapabilityRequest:
        return CapabilityRequest(
            task_type=TaskType.LLM_RED_TEAM,
            workspace_root=self.workspace,
            campaign_manifest=str(manifest) if manifest is not None else None,
        )

    def capability(self, runner: FakeStagingRunner) -> GarakCapability:
        return GarakCapability(
            runner_factory=lambda: runner,
            clock=lambda: datetime(2026, 9, 7, 22, 15, tzinfo=timezone.utc),
        )

    def test_emits_only_aggregate_evaluation_evidence(self) -> None:
        runner = FakeStagingRunner(
            GarakRunResult.completed(
                GarakReportSummary(attempt_count=2, failure_count=1, hit_count=1)
            )
        )

        result = self.capability(runner).run(self.request(self.manifest))

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.control_evidence), 1)
        evidence = result.control_evidence[0]
        self.assertEqual(evidence.category, "garak_evaluation")
        self.assertEqual(evidence.identifier, "garak-synthetic-staging-smoke-v1")
        self.assertEqual(
            evidence.metrics,
            (("attempt_count", 2), ("failure_count", 1), ("hit_count", 1)),
        )
        self.assertEqual(runner.manifests, [self.manifest])
        self.assertNotIn("prompt", repr(result).lower())
        self.assertNotIn("response", repr(result).lower())

    def test_rejects_missing_or_altered_manifest_without_starting_runner(self) -> None:
        runner = FakeStagingRunner(
            GarakRunResult.completed(GarakReportSummary(1, 0, 0))
        )

        missing = self.capability(runner).run(self.request())

        self.assertEqual(missing.status, CapabilityStatus.FAILED)
        self.assertEqual(missing.error_code, ErrorCode.MISSING_CAMPAIGN_MANIFEST)

        altered = json.loads(self.manifest.read_text(encoding="utf-8"))
        altered["target"]["host"] = "example.com"
        altered_path = Path(self.temp_dir.name) / "altered.json"
        altered_path.write_text(json.dumps(altered), encoding="utf-8")
        invalid = self.capability(runner).run(self.request(altered_path))

        self.assertEqual(invalid.status, CapabilityStatus.FAILED)
        self.assertEqual(invalid.error_code, ErrorCode.INVALID_CAMPAIGN_MANIFEST)
        self.assertEqual(runner.manifests, [])

    def test_preserves_timeout_as_a_typed_incomplete_result(self) -> None:
        runner = FakeStagingRunner(GarakRunResult.incomplete(GarakRunError.TIMEOUT))

        result = self.capability(runner).run(self.request(self.manifest))

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_TIMEOUT)

    def test_reports_unavailable_runner_without_executing_campaign(self) -> None:
        def unavailable_runner() -> FakeStagingRunner:
            raise ValueError("missing reviewed executable")

        capability = GarakCapability(
            runner_factory=unavailable_runner,
            clock=lambda: datetime(2026, 9, 7, 22, 15, tzinfo=timezone.utc),
        )

        result = capability.run(self.request(self.manifest))

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)

    def test_requires_pinned_config_and_rejects_expired_campaign(self) -> None:
        self.assertTrue(require_approved_staging_config().is_file())

        with self.assertRaisesRegex(CampaignManifestError, "campaign-window-expired"):
            load_approved_staging_campaign(
                self.manifest,
                now=datetime(2026, 9, 7, 22, 21, tzinfo=timezone.utc),
            )

    def test_cli_serializes_safe_campaign_metrics(self) -> None:
        runner = FakeStagingRunner(
            GarakRunResult.completed(GarakReportSummary(1, 0, 0))
        )
        output = io.StringIO()
        state_root = Path(self.temp_dir.name) / "state"
        old_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = str(state_root)
        try:
            exit_code = main(
                [
                    "run",
                    "--task",
                    "llm_red_team",
                    "--workspace-root",
                    str(self.workspace),
                    "--campaign-manifest",
                    str(self.manifest),
                ],
                router=Router((self.capability(runner),)),
                output=output,
                evidence_store=EvidenceStore(state_root, self.workspace),
            )
        finally:
            if old_state_home is None:
                os.environ.pop("XDG_STATE_HOME", None)
            else:
                os.environ["XDG_STATE_HOME"] = old_state_home

        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        evidence = report["results"][0]["control_evidence"][0]
        self.assertEqual(evidence["identifier"], "garak-synthetic-staging-smoke-v1")
        self.assertEqual(evidence["metrics"], {"attempt_count": 1, "failure_count": 0, "hit_count": 0})
        persisted = next(state_root.glob("*.json")).read_text(encoding="utf-8")
        self.assertNotIn("prompt", persisted.lower())
        self.assertNotIn("response", persisted.lower())


if __name__ == "__main__":
    unittest.main()
