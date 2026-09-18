"""Safe adapter for Bandit's local JSON output."""

from __future__ import annotations

import json

# Required for the bounded local Bandit adapter; invocation uses fixed tokens.
import subprocess  # nosec B404
from collections.abc import Callable, Mapping
from pathlib import Path

from core.capability import (
    EXCLUDED_PATH_PARTS,
    Capability,
    CapabilityRequest,
    CapabilityResult,
    ErrorCode,
    TaskType,
)
from core.finding import Finding


Runner = Callable[..., subprocess.CompletedProcess[str]]


class UnsafeToolOutputError(ValueError):
    """Bandit reported a finding outside the adapter's authorized scope."""


class BanditCapability(Capability):
    """Run Bandit locally and normalize only validated findings."""

    name = "bandit"
    version = "1"
    supported_task_types = frozenset({TaskType.CODE_ANALYSIS})

    def __init__(self, runner: Runner = subprocess.run) -> None:
        self._runner = runner

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        command = [
            "bandit",
            "-r",
            str(request.target),
            "-f",
            "json",
            "-x",
            self._exclusion_patterns(),
        ]
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=request.timeout_seconds,
                cwd=request.workspace_root,
            )
        except FileNotFoundError:
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        except subprocess.TimeoutExpired:
            return CapabilityResult.incomplete(ErrorCode.TOOL_TIMEOUT)
        except OSError:
            return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)

        if completed.returncode not in {0, 1}:
            return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)

        return self._parse_output(completed.stdout, request)

    @staticmethod
    def _exclusion_patterns() -> str:
        return ",".join(f"*/{part}/*" for part in sorted(EXCLUDED_PATH_PARTS))

    def _parse_output(
        self, output: str, request: CapabilityRequest
    ) -> CapabilityResult:
        try:
            payload = json.loads(output)
            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                raise ValueError("missing results list")
            findings = tuple(
                self._normalize_finding(result, request)
                for result in payload["results"]
            )
        except UnsafeToolOutputError:
            return CapabilityResult.incomplete(ErrorCode.UNSAFE_TOOL_OUTPUT)
        except (TypeError, ValueError, json.JSONDecodeError):
            return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)

        return CapabilityResult.completed(findings)

    def _normalize_finding(
        self, result: object, request: CapabilityRequest
    ) -> Finding:
        if not isinstance(result, Mapping):
            raise ValueError("result must be an object")

        filename = self._required_string(result, "filename")
        line = result.get("line_number")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError("line_number must be a positive integer")

        severity = self._required_string(result, "issue_severity").upper()
        rule_id = self._required_string(result, "test_id")
        description = self._required_string(result, "issue_text")
        confidence = self._confidence(result.get("issue_confidence"))
        cwe = self._cwe(result.get("issue_cwe"))
        extra = self._extra(result)

        return Finding(
            source=self.name,
            file_path=self._normalize_path(filename, request),
            line=line,
            severity=severity,
            rule_id=rule_id,
            description=description,
            confidence=confidence,
            cwe=cwe,
            extra=extra,
        )

    @staticmethod
    def _required_string(result: Mapping[str, object], key: str) -> str:
        value = result.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a non-empty string")
        return value

    @staticmethod
    def _confidence(value: object) -> float | None:
        if not isinstance(value, str):
            raise ValueError("issue_confidence must be a string")
        return {"LOW": 0.33, "MEDIUM": 0.66, "HIGH": 1.0}.get(value.upper())

    @staticmethod
    def _cwe(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ValueError("issue_cwe must be an object")
        identifier = value.get("id")
        if identifier is None:
            return None
        if not isinstance(identifier, int) or isinstance(identifier, bool):
            raise ValueError("issue_cwe.id must be an integer")
        return f"CWE-{identifier}"

    @staticmethod
    def _extra(result: Mapping[str, object]) -> Mapping[str, object]:
        extra: dict[str, object] = {}
        for key in ("test_name", "more_info"):
            value = result.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{key} must be a string")
                extra[key] = value
        return extra

    @staticmethod
    def _normalize_path(filename: str, request: CapabilityRequest) -> str:
        reported_path = Path(filename)
        if reported_path.is_absolute():
            candidates = (reported_path.resolve(),)
        else:
            candidates = (
                (request.workspace_root / reported_path).resolve(),
                (request.target / reported_path).resolve(),
            )

        for candidate in candidates:
            try:
                relative = candidate.relative_to(request.target)
            except ValueError:
                continue
            if any(part in EXCLUDED_PATH_PARTS for part in relative.parts):
                raise UnsafeToolOutputError(filename)
            return relative.as_posix()

        raise UnsafeToolOutputError(filename)
