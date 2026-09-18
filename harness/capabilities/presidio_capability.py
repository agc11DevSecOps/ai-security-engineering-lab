"""Local-only adapter that reduces Presidio PII detections to control evidence."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from core.capability import (
    Capability,
    CapabilityRequest,
    CapabilityResult,
    ControlEvidence,
    ErrorCode,
    TaskType,
)


SCORE_THRESHOLD = 0.3
MAX_CONTROL_EVIDENCE = 16
SUPPORTED_ENTITY_TYPES = frozenset(
    {
        "CREDIT_CARD",
        "EMAIL_ADDRESS",
        "IBAN_CODE",
        "IP_ADDRESS",
        "PERSON",
        "PHONE_NUMBER",
        "US_SSN",
    }
)
PERSON_STOPWORDS = frozenset(
    {"adios", "adiós", "buenos dias", "buenos días", "gracias", "hola"}
)
Analyzer = Callable[..., Iterable[object]]
AnalyzerLoader = Callable[[], Analyzer]


def load_local_analyzer() -> Analyzer:
    """Build the reviewed local English/Spanish Presidio engine without downloads."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "en", "model_name": "en_core_web_lg"},
                {"lang_code": "es", "model_name": "es_core_news_lg"},
            ],
        }
    )
    return AnalyzerEngine(
        nlp_engine=provider.create_engine(), supported_languages=["en", "es"]
    ).analyze


class PresidioCapability(Capability):
    """Report a bounded, redacted PII signal without changing the message."""

    name = "presidio"
    version = "2-local"
    supported_task_types = frozenset({TaskType.INPUT_GUARD})

    def __init__(self, loader: AnalyzerLoader = load_local_analyzer) -> None:
        self._loader = loader
        self._analyzer: Analyzer | None = None

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        analyzer = self._get_analyzer()
        if analyzer is None:
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        try:
            detections = tuple(
                detection
                for language in ("en", "es")
                for detection in analyzer(
                    text=request.message,
                    language=language,
                    score_threshold=SCORE_THRESHOLD,
                )
            )
        except Exception:
            return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)
        return self._normalize_detections(detections, request.message)

    def _get_analyzer(self) -> Analyzer | None:
        if self._analyzer is not None:
            return self._analyzer
        try:
            self._analyzer = self._loader()
        except (ImportError, OSError, ValueError):
            return None
        return self._analyzer

    @staticmethod
    def _normalize_detections(
        detections: Iterable[object], message: str
    ) -> CapabilityResult:
        evidence_by_entity: dict[str, ControlEvidence] = {}
        for detection in detections:
            entity_type = getattr(detection, "entity_type", None)
            score = getattr(detection, "score", None)
            start = getattr(detection, "start", None)
            end = getattr(detection, "end", None)
            if (
                not isinstance(entity_type, str)
                or not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not 0 <= score <= 1
                or not isinstance(start, int)
                or not isinstance(end, int)
                or not 0 <= start < end <= len(message)
            ):
                return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
            if entity_type not in SUPPORTED_ENTITY_TYPES:
                continue
            if (
                entity_type == "PERSON"
                and message[start:end].strip().lower() in PERSON_STOPWORDS
            ):
                continue
            evidence = ControlEvidence(
                rule_id=f"PII_{entity_type}", category="pii", confidence=float(score)
            )
            previous = evidence_by_entity.get(entity_type)
            if previous is None or evidence.confidence > previous.confidence:
                evidence_by_entity[entity_type] = evidence
        evidence = tuple(
            evidence_by_entity[entity_type]
            for entity_type in sorted(evidence_by_entity)[:MAX_CONTROL_EVIDENCE]
        )
        return CapabilityResult.observed(evidence)
