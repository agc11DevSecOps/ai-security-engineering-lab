"""Safe adapter for Vulnhuntr's local JSON output (Ollama loader only)."""

from __future__ import annotations

import json
import math
import os
import shutil
import tempfile

# Required for the bounded local Vulnhuntr adapter; invocation uses fixed tokens.
import subprocess  # nosec B404
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from core.capability import (
    EXCLUDED_PATH_PARTS,
    Capability,
    CapabilityRequest,
    CapabilityResult,
    CapabilityStatus,
    ErrorCode,
    TaskType,
)
from core.finding import Finding


Runner = Callable[..., subprocess.CompletedProcess[str]]

DEFAULT_MODEL = "qwen2.5-coder:7b-instruct"


class UnsafeToolOutputError(ValueError):
    """Vulnhuntr reported a finding outside the adapter's authorized scope."""


class VulnhuntrCapability(Capability):
    """Run Vulnhuntr locally per file and normalize only validated findings."""

    name = "vulnhuntr"
    version = "1"
    supported_task_types = frozenset({TaskType.CODE_ANALYSIS})

    def __init__(
        self,
        runner: Runner = subprocess.run,
        *,
        vulnhuntr_bin: str | None = None,
        model: str = DEFAULT_MODEL,
    ) -> None:
        self._runner = runner
        self._vulnhuntr_bin = vulnhuntr_bin or self._default_bin()
        self._model = model

    @staticmethod
    def _default_bin() -> str | None:
        """Resolve the binary from `VULNHUNTR_BIN` or PATH, never from a developer home."""
        return os.environ.get("VULNHUNTR_BIN") or shutil.which("vulnhuntr")

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        files = self._discover_python_files(request.target)
        findings: list[Finding] = []
        for relative_file in files:
            result = self._analyze_file(request, relative_file)
            if result.status is not CapabilityStatus.COMPLETED:
                # Keep already validated findings visible when a later file fails.
                return CapabilityResult(
                    status=result.status,
                    findings=tuple(findings),
                    error_code=result.error_code,
                )
            findings.extend(result.findings)
        return CapabilityResult.completed(tuple(findings))

    def _discover_python_files(self, target: Path) -> list[Path]:
        files = []
        for py_file in target.rglob("*.py"):
            try:
                relative = py_file.relative_to(target)
            except ValueError:
                continue
            if any(part in EXCLUDED_PATH_PARTS for part in relative.parts):
                continue
            files.append(py_file.resolve())
        return sorted(files)

    def _analyze_file(
        self, request: CapabilityRequest, source_file: Path
    ) -> CapabilityResult:
        if self._vulnhuntr_bin is None:
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        descriptor, temporary_name = tempfile.mkstemp(suffix=".json")
        os.close(descriptor)
        json_path = Path(temporary_name)
        command = [
            self._vulnhuntr_bin,
            "-r",
            str(request.target),
            "-a",
            str(source_file),
            "-l",
            "ollama",
            "--no-checkpoint",
            "--json",
            str(json_path),
        ]
        environment = {**os.environ, "OLLAMA_MODEL": self._model}

        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=request.timeout_seconds,
                env=environment,
                cwd=str(request.target),
            )
            if completed.returncode != 0:
                return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)
            text = json_path.read_text(encoding="utf-8")
            return self._parse_output(text, request)
        except FileNotFoundError:
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        except subprocess.TimeoutExpired:
            return CapabilityResult.incomplete(ErrorCode.TOOL_TIMEOUT)
        except OSError:
            return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return CapabilityResult.incomplete(ErrorCode.MALFORMED_TOOL_OUTPUT)
        finally:
            json_path.unlink(missing_ok=True)

    def _parse_output(self, text: str, request: CapabilityRequest) -> CapabilityResult:
        try:
            payload = json.loads(text)
            if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
                raise ValueError("missing findings list")
            findings = tuple(
                self._normalize_finding(finding, request)
                for finding in payload["findings"]
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
            raise ValueError("finding must be an object")

        file_path = self._normalize_path(
            self._required_string(result, "file_path"), request
        )
        rule_id = self._required_string(result, "rule_id")
        severity = self._required_string(result, "severity").upper()
        description = self._description(result)
        line = self._line(result.get("location"))
        confidence = self._confidence(result.get("confidence_score"))
        cwe = self._optional_string(result.get("cwe_id"))
        poc = self._optional_string(result.get("poc"))
        title = self._optional_string(result.get("title"))
        extra = {"title": title} if title else {}

        return Finding(
            source=self.name,
            file_path=file_path,
            line=line,
            severity=severity,
            rule_id=rule_id,
            description=description,
            confidence=confidence,
            cwe=cwe,
            poc=poc,
            extra=extra,
        )

    @staticmethod
    def _required_string(result: Mapping[str, object], key: str) -> str:
        value = result.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a non-empty string")
        return value

    @staticmethod
    def _optional_string(value: object) -> str | None:
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _description(result: Mapping[str, object]) -> str:
        for key in ("analysis", "description"):
            value = result.get(key)
            if isinstance(value, str) and value:
                return value
        raise ValueError("finding must include an analysis or description")

    @staticmethod
    def _line(location: object) -> int | None:
        if not isinstance(location, Mapping):
            return None
        start_line = location.get("start_line")
        if isinstance(start_line, int) and not isinstance(start_line, bool) and start_line >= 1:
            return start_line
        return None

    @staticmethod
    def _confidence(value: object) -> float | None:
        if value is None:
            return None
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 10
        ):
            raise ValueError("confidence_score must be a finite number from zero to ten")
        return value / 10.0

    def _normalize_path(self, filename: str, request: CapabilityRequest) -> str:
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
