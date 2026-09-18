"""Local-only adapter for Meta Llama Prompt Guard 2 evidence."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from core.capability import (
    Capability,
    CapabilityRequest,
    CapabilityResult,
    ControlEvidence,
    ErrorCode,
    TaskType,
)


MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"
MODEL_REVISION = "a8ded8e697ce7c355e395a0df51f94adb4a2fd27"
MAX_MODEL_TOKENS = 512
Classifier = Callable[..., object]
ClassifierLoader = Callable[[], Classifier]


def load_local_classifier() -> Classifier:
    """Load only reviewed local safetensors; never fetch or execute remote code."""
    from transformers import (  # Imported lazily so code analysis needs no ML stack.
        AutoModelForSequenceClassification,
        AutoTokenizer,
        pipeline,
    )

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        local_files_only=True,
        trust_remote_code=False,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True,
    )
    return pipeline("text-classification", model=model, tokenizer=tokenizer, device=-1)


class PromptGuardCapability(Capability):
    """Normalize Prompt Guard classifications into non-enforcing evidence."""

    name = "prompt-guard-2"
    version = "2-86m-local"
    supported_task_types = frozenset({TaskType.INPUT_GUARD})

    def __init__(self, loader: ClassifierLoader = load_local_classifier) -> None:
        self._loader = loader
        self._classifier: Classifier | None = None

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        classifier = self._get_classifier()
        if classifier is None:
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        try:
            output = classifier(
                request.message,
                truncation=True,
                max_length=MAX_MODEL_TOKENS,
            )
        except Exception:
            return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)
        return self._normalize_output(output)

    def _get_classifier(self) -> Classifier | None:
        if self._classifier is not None:
            return self._classifier
        try:
            self._classifier = self._loader()
        except (ImportError, OSError, ValueError):
            return None
        return self._classifier

    @staticmethod
    def _normalize_output(output: object) -> CapabilityResult:
        if not isinstance(output, list) or len(output) != 1:
            return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
        result = output[0]
        if not isinstance(result, Mapping):
            return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
        label = result.get("label")
        score = result.get("score")
        if (
            not isinstance(label, str)
            or not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not 0 <= score <= 1
        ):
            return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
        if label in {"LABEL_0", "BENIGN"}:
            return CapabilityResult.observed(())
        if label in {"LABEL_1", "MALICIOUS"}:
            return CapabilityResult.observed(
                (
                    ControlEvidence(
                        rule_id="PROMPT_INJECTION",
                        category="prompt_injection",
                        confidence=float(score),
                    ),
                )
            )
        return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
