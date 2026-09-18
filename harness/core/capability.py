"""Typed, safe boundary between the router and a security capability."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

from core.finding import Finding


class TaskType(str, Enum):
    """Task types supported by the initial harness vocabulary."""

    CODE_ANALYSIS = "code_analysis"
    INPUT_GUARD = "input_guard"
    LLM_RED_TEAM = "llm_red_team"


class CapabilityStatus(str, Enum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class ErrorCode(str, Enum):
    RELATIVE_PATH = "relative_path"
    OUTSIDE_WORKSPACE = "outside_workspace"
    EXCLUDED_PATH = "excluded_path"
    TARGET_NOT_DIRECTORY = "target_not_directory"
    UNSUPPORTED_TASK = "unsupported_task"
    REMOTE_NOT_ALLOWED = "remote_not_allowed"
    INVALID_RETENTION = "invalid_retention"
    INVALID_TIMEOUT = "invalid_timeout"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_TIMEOUT = "tool_timeout"
    TOOL_FAILED = "tool_failed"
    MALFORMED_TOOL_OUTPUT = "malformed_tool_output"
    UNSAFE_TOOL_OUTPUT = "unsafe_tool_output"
    INVALID_RESULT = "invalid_result"
    INTERNAL_ERROR = "internal_error"
    MISSING_MESSAGE = "missing_message"
    INVALID_MESSAGE = "invalid_message"
    MESSAGE_TOO_LARGE = "message_too_large"
    UNEXPECTED_MESSAGE = "unexpected_message"
    UNEXPECTED_TARGET = "unexpected_target"
    RAW_EVIDENCE_NOT_ALLOWED = "raw_evidence_not_allowed"
    MISSING_CAMPAIGN_MANIFEST = "missing_campaign_manifest"
    INVALID_CAMPAIGN_MANIFEST = "invalid_campaign_manifest"


EXCLUDED_PATH_PARTS = frozenset(
    {
        ".aws",
        ".git",
        ".gnupg",
        ".kube",
        ".ssh",
        ".venv",
        "__pycache__",
        "node_modules",
        "vendor",
    }
)
MAX_MESSAGE_BYTES = 16_384


class RequestValidationError(ValueError):
    """A safe, stable validation failure for an untrusted request."""

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class CapabilityRequest:
    task_type: TaskType
    workspace_root: Path
    target: Path | None = None
    timeout_seconds: int = 300
    allow_remote: bool = False
    allow_raw_evidence: bool = False
    raw_evidence_retention_days: int | None = None
    message: str | None = None
    campaign_manifest: str | None = None


@dataclass(frozen=True)
class CapabilityProvenance:
    capability_name: str
    capability_version: str
    target: Path | None


@dataclass(frozen=True)
class ControlEvidence:
    """Normalized guard evidence that never instructs a caller to block."""

    rule_id: str
    category: str
    confidence: float | None = None
    identifier: str | None = None
    metrics: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id:
            raise TypeError("rule_id must be a non-empty string")
        if not isinstance(self.category, str) or not self.category:
            raise TypeError("category must be a non-empty string")
        if self.confidence is not None and (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not 0 <= self.confidence <= 1
        ):
            raise TypeError("confidence must be a number between zero and one")
        if self.identifier is not None and (
            not isinstance(self.identifier, str) or not self.identifier
        ):
            raise TypeError("identifier must be a non-empty string or None")
        if not isinstance(self.metrics, tuple) or not all(
            isinstance(key, str)
            and key
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
            for key, value in self.metrics
        ):
            raise TypeError("metrics must be non-negative integer key-value pairs")


@dataclass(frozen=True)
class CapabilityResult:
    status: CapabilityStatus
    findings: tuple[Finding, ...]
    control_evidence: tuple[ControlEvidence, ...] = ()
    error_code: ErrorCode | None = None
    provenance: CapabilityProvenance | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, CapabilityStatus):
            raise TypeError("status must be a CapabilityStatus")
        if not isinstance(self.findings, tuple):
            raise TypeError("findings must be a tuple")
        if not all(isinstance(finding, Finding) for finding in self.findings):
            raise TypeError("findings must contain only Finding instances")
        if not isinstance(self.control_evidence, tuple):
            raise TypeError("control_evidence must be a tuple")
        if not all(isinstance(item, ControlEvidence) for item in self.control_evidence):
            raise TypeError("control_evidence must contain only ControlEvidence instances")
        if self.error_code is not None and not isinstance(self.error_code, ErrorCode):
            raise TypeError("error_code must be an ErrorCode or None")
        if self.status is CapabilityStatus.COMPLETED and self.error_code is not None:
            raise ValueError("completed results cannot include an error code")
        if self.status is not CapabilityStatus.COMPLETED and self.error_code is None:
            raise ValueError("incomplete and failed results require an error code")
        if self.control_evidence and self.findings:
            raise ValueError("a completed result cannot carry both findings and control evidence")
        if self.status is not CapabilityStatus.COMPLETED and self.control_evidence:
            raise ValueError("incomplete and failed results cannot carry control evidence")

    @classmethod
    def completed(cls, findings: tuple[Finding, ...]) -> CapabilityResult:
        return cls(status=CapabilityStatus.COMPLETED, findings=findings)

    @classmethod
    def observed(cls, control_evidence: tuple[ControlEvidence, ...]) -> CapabilityResult:
        return cls(
            status=CapabilityStatus.COMPLETED,
            findings=(),
            control_evidence=control_evidence,
        )

    @classmethod
    def failed(cls, error_code: ErrorCode) -> CapabilityResult:
        return cls(
            status=CapabilityStatus.FAILED,
            findings=(),
            error_code=error_code,
        )

    @classmethod
    def incomplete(cls, error_code: ErrorCode) -> CapabilityResult:
        return cls(
            status=CapabilityStatus.INCOMPLETE,
            findings=(),
            error_code=error_code,
        )


def validate_request(request: CapabilityRequest) -> CapabilityRequest:
    """Canonicalize and constrain an untrusted request."""

    try:
        workspace_root = Path(request.workspace_root)
    except TypeError as error:
        raise RequestValidationError(ErrorCode.RELATIVE_PATH) from error

    if not workspace_root.is_absolute():
        raise RequestValidationError(ErrorCode.RELATIVE_PATH)
    if request.allow_remote:
        raise RequestValidationError(ErrorCode.REMOTE_NOT_ALLOWED)
    if request.task_type is TaskType.INPUT_GUARD and request.allow_raw_evidence:
        raise RequestValidationError(ErrorCode.RAW_EVIDENCE_NOT_ALLOWED)
    if (
        not isinstance(request.timeout_seconds, int)
        or isinstance(request.timeout_seconds, bool)
        or not 1 <= request.timeout_seconds <= 3_600
    ):
        raise RequestValidationError(ErrorCode.INVALID_TIMEOUT)
    if request.allow_raw_evidence:
        retention = request.raw_evidence_retention_days
        if (
            not isinstance(retention, int)
            or isinstance(retention, bool)
            or not 1 <= retention <= 7
        ):
            raise RequestValidationError(ErrorCode.INVALID_RETENTION)
    elif request.raw_evidence_retention_days is not None:
        raise RequestValidationError(ErrorCode.INVALID_RETENTION)

    try:
        resolved_workspace = workspace_root.resolve()
    except (OSError, RuntimeError) as error:
        raise RequestValidationError(ErrorCode.TARGET_NOT_DIRECTORY) from error
    if not resolved_workspace.is_dir():
        raise RequestValidationError(ErrorCode.TARGET_NOT_DIRECTORY)

    if request.task_type is TaskType.CODE_ANALYSIS:
        return _validate_code_analysis(request, resolved_workspace)
    if request.task_type is TaskType.INPUT_GUARD:
        return _validate_input_guard(request, resolved_workspace)
    if request.task_type is TaskType.LLM_RED_TEAM:
        # llm_red_team requires campaign_manifest validation
        # target must be None for llm_red_team
        if request.target is not None:
            raise RequestValidationError(ErrorCode.UNEXPECTED_TARGET)
        # campaign_manifest will be checked by the capability
        return replace(
            request,
            target=None,
            workspace_root=resolved_workspace,
        )
    raise RequestValidationError(ErrorCode.UNSUPPORTED_TASK)


def _validate_code_analysis(
    request: CapabilityRequest, resolved_workspace: Path
) -> CapabilityRequest:
    if request.message is not None:
        raise RequestValidationError(ErrorCode.UNEXPECTED_MESSAGE)
    try:
        target = Path(request.target)
    except TypeError as error:
        raise RequestValidationError(ErrorCode.RELATIVE_PATH) from error

    if not target.is_absolute():
        raise RequestValidationError(ErrorCode.RELATIVE_PATH)

    try:
        resolved_target = target.resolve()
    except (OSError, RuntimeError) as error:
        raise RequestValidationError(ErrorCode.TARGET_NOT_DIRECTORY) from error
    if not resolved_target.is_dir():
        raise RequestValidationError(ErrorCode.TARGET_NOT_DIRECTORY)

    try:
        relative_target = resolved_target.relative_to(resolved_workspace)
    except ValueError as error:
        raise RequestValidationError(ErrorCode.OUTSIDE_WORKSPACE) from error

    if any(part in EXCLUDED_PATH_PARTS for part in relative_target.parts):
        raise RequestValidationError(ErrorCode.EXCLUDED_PATH)

    return replace(
        request,
        target=resolved_target,
        workspace_root=resolved_workspace,
    )


def _validate_input_guard(
    request: CapabilityRequest, resolved_workspace: Path
) -> CapabilityRequest:
    if request.target is not None:
        raise RequestValidationError(ErrorCode.UNEXPECTED_TARGET)
    if not isinstance(request.message, str) or not request.message.strip():
        raise RequestValidationError(ErrorCode.MISSING_MESSAGE)
    try:
        message_size = len(request.message.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise RequestValidationError(ErrorCode.INVALID_MESSAGE) from error
    if message_size > MAX_MESSAGE_BYTES:
        raise RequestValidationError(ErrorCode.MESSAGE_TOO_LARGE)
    return replace(
        request,
        target=None,
        workspace_root=resolved_workspace,
    )


class Capability(ABC):
    """Base class that enforces the router-facing capability contract."""

    name: str
    version: str
    supported_task_types: frozenset[TaskType]

    def run(self, request: CapabilityRequest) -> CapabilityResult:
        try:
            validated_request = validate_request(request)
        except RequestValidationError as error:
            return CapabilityResult.failed(error.code)

        if validated_request.task_type not in self.supported_task_types:
            return CapabilityResult.failed(ErrorCode.UNSUPPORTED_TASK)

        try:
            result = self._run(validated_request)
        except Exception:
            return CapabilityResult.failed(ErrorCode.INTERNAL_ERROR)

        if not isinstance(result, CapabilityResult):
            return CapabilityResult.failed(ErrorCode.INVALID_RESULT)

        return replace(
            result,
            provenance=CapabilityProvenance(
                capability_name=self.name,
                capability_version=self.version,
                target=validated_request.target,
            ),
        )

    @abstractmethod
    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        """Run the capability after boundary validation has completed."""
