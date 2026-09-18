from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


PHASE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PHASE_ROOT))

from capabilities.presidio_capability import (  # noqa: E402
    SCORE_THRESHOLD,
    PresidioCapability,
)
from core.capability import (  # noqa: E402
    CapabilityRequest,
    CapabilityStatus,
    ErrorCode,
    TaskType,
)


def detection(entity_type: str, score: float, start: int, end: int) -> object:
    return SimpleNamespace(entity_type=entity_type, score=score, start=start, end=end)


class PresidioCapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name) / "workspace"
        self.workspace.mkdir()
        self.message = "Hola, escribe a ana@example.com o llama al +34 611 222 333"
        self.request = CapabilityRequest(
            task_type=TaskType.INPUT_GUARD,
            workspace_root=self.workspace,
            message=self.message,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_emits_one_highest_confidence_record_per_approved_entity(self) -> None:
        calls: list[dict[str, object]] = []
        email_start = self.message.index("ana@example.com")
        email_end = email_start + len("ana@example.com")
        phone_start = self.message.index("+34")

        def analyzer(**kwargs: object) -> list[object]:
            calls.append(kwargs)
            return [
                detection("EMAIL_ADDRESS", 0.7, email_start, email_end),
                detection("EMAIL_ADDRESS", 0.9, email_start, email_end),
                detection("PHONE_NUMBER", 0.4, phone_start, len(self.message)),
                detection("URL", 0.8, 0, 4),
            ]

        result = PresidioCapability(lambda: analyzer).run(self.request)

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(
            [(item.rule_id, item.confidence) for item in result.control_evidence],
            [("PII_EMAIL_ADDRESS", 0.9), ("PII_PHONE_NUMBER", 0.4)],
        )
        self.assertEqual(
            calls,
            [
                {"text": self.message, "language": "en", "score_threshold": SCORE_THRESHOLD},
                {"text": self.message, "language": "es", "score_threshold": SCORE_THRESHOLD},
            ],
        )

    def test_filters_known_person_stopwords_without_returning_text(self) -> None:
        result = PresidioCapability(
            lambda: lambda **_kwargs: [detection("PERSON", 0.8, 0, 4)]
        ).run(self.request)

        self.assertEqual(result.status, CapabilityStatus.COMPLETED)
        self.assertEqual(result.control_evidence, ())

    def test_missing_local_stack_is_unavailable(self) -> None:
        def unavailable() -> object:
            raise ImportError("presidio is unavailable")

        result = PresidioCapability(unavailable).run(self.request)

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_UNAVAILABLE)

    def test_analyzer_failure_is_incomplete(self) -> None:
        def failing_analyzer(**_kwargs: object) -> object:
            raise RuntimeError("model failure")

        result = PresidioCapability(lambda: failing_analyzer).run(self.request)

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.TOOL_FAILED)

    def test_malformed_detection_is_rejected(self) -> None:
        malformed = SimpleNamespace(entity_type="EMAIL_ADDRESS", score=0.9, start=0, end=999)

        result = PresidioCapability(lambda: lambda **_kwargs: [malformed]).run(self.request)

        self.assertEqual(result.status, CapabilityStatus.INCOMPLETE)
        self.assertEqual(result.error_code, ErrorCode.MALFORMED_TOOL_OUTPUT)


if __name__ == "__main__":
    unittest.main()
