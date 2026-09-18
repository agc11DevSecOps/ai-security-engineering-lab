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
    ErrorCode,
    TaskType,
)
from core.finding import Finding  # noqa: E402
from core.router import Router  # noqa: E402


class FakeCapability(Capability):
    name = "fake"
    version = "test"

    def __init__(self, task_types: frozenset[TaskType]) -> None:
        self.supported_task_types = task_types
        self.calls = 0

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        self.calls += 1
        return CapabilityResult.completed(
            (
                Finding(
                    source=self.name,
                    file_path="app.py",
                    line=1,
                    severity="LOW",
                    rule_id="TEST001",
                    description="Router test finding",
                ),
            )
        )


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.target = self.workspace / "target"
        self.target.mkdir()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def request(self, task_type: TaskType = TaskType.CODE_ANALYSIS) -> CapabilityRequest:
        return CapabilityRequest(
            task_type=task_type,
            target=self.target,
            workspace_root=self.workspace,
        )

    def test_selects_only_capabilities_supporting_the_task(self) -> None:
        code_capability = FakeCapability(frozenset({TaskType.CODE_ANALYSIS}))
        guard_capability = FakeCapability(frozenset({TaskType.INPUT_GUARD}))

        selected = Router((code_capability, guard_capability)).select(self.request())

        self.assertEqual(selected, (code_capability,))

    def test_run_preserves_each_selected_result(self) -> None:
        first = FakeCapability(frozenset({TaskType.CODE_ANALYSIS}))
        second = FakeCapability(frozenset({TaskType.CODE_ANALYSIS}))

        results = Router((first, second)).run(self.request())

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.status is CapabilityStatus.COMPLETED for result in results))
        self.assertEqual(first.calls, 1)
        self.assertEqual(second.calls, 1)

    def test_run_returns_a_failure_when_no_capability_supports_the_task(self) -> None:
        router = Router((FakeCapability(frozenset({TaskType.INPUT_GUARD})),))

        results = router.run(self.request())

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, CapabilityStatus.FAILED)
        self.assertEqual(results[0].error_code, ErrorCode.UNSUPPORTED_TASK)


if __name__ == "__main__":
    unittest.main()
