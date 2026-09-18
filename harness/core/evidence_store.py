"""Private, redacted local storage for completed harness executions."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.capability import (
    CapabilityRequest,
    CapabilityResult,
    ControlEvidence,
    RequestValidationError,
    validate_request,
)
from core.finding import Finding


METADATA_RETENTION_DAYS = 90
MAX_RAW_EVIDENCE_BYTES = 1_048_576
SCHEMA_VERSION = 1


class EvidenceStoreError(ValueError):
    """A stable refusal to persist unsafe or unapproved evidence."""


@dataclass(frozen=True)
class EvidenceRecord:
    record_id: str
    metadata_path: Path
    raw_path: Path | None


@dataclass(frozen=True)
class CleanupResult:
    raw_artifacts: int
    metadata_records: int


class EvidenceStore:
    """Persist redacted records outside one canonical workspace root."""

    def __init__(self, root: Path, workspace_root: Path) -> None:
        self._workspace_root = self._canonical_directory(workspace_root, "workspace root")
        self._root = self._canonical_absolute_path(root, "evidence root")
        self._assert_safe_root()

    def write(
        self,
        request: CapabilityRequest,
        results: Iterable[CapabilityResult],
        *,
        raw_evidence: bytes | None = None,
        now: datetime | None = None,
    ) -> EvidenceRecord:
        """Write redacted metadata and an explicitly approved raw artifact."""
        try:
            validated_request = validate_request(request)
        except RequestValidationError as error:
            raise EvidenceStoreError(error.code.value) from error
        if validated_request.workspace_root != self._workspace_root:
            raise EvidenceStoreError("request workspace does not match evidence store")
        if raw_evidence is not None and not validated_request.allow_raw_evidence:
            raise EvidenceStoreError("raw evidence requires explicit opt-in")
        if raw_evidence is not None and not isinstance(raw_evidence, bytes):
            raise EvidenceStoreError("raw evidence must be bytes")
        if raw_evidence is not None and len(raw_evidence) > MAX_RAW_EVIDENCE_BYTES:
            raise EvidenceStoreError("raw evidence exceeds the 1 MiB limit")

        timestamp = self._timestamp(now)
        serialized_results = tuple(self._serialize_result(result) for result in results)
        self.cleanup(now=timestamp)
        self._ensure_root()

        record_id = uuid.uuid4().hex
        metadata_path = self._root / f"{record_id}.json"
        raw_path = self._root / f"{record_id}.raw" if raw_evidence is not None else None
        raw_expires_at = (
            timestamp + timedelta(days=validated_request.raw_evidence_retention_days)
            if raw_evidence is not None
            else None
        )
        payload = {
            "schema_version": SCHEMA_VERSION,
            "created_at": timestamp.isoformat(),
            "metadata_expires_at": (timestamp + timedelta(days=METADATA_RETENTION_DAYS)).isoformat(),
            "raw_evidence_expires_at": raw_expires_at.isoformat() if raw_expires_at else None,
            "task_type": validated_request.task_type.value,
            "target_sha256": (
                hashlib.sha256(str(validated_request.target).encode("utf-8")).hexdigest()
                if validated_request.target is not None
                else None
            ),
            "results": serialized_results,
        }

        try:
            if raw_path is not None:
                self._atomic_write(raw_path, raw_evidence)
            self._atomic_write(
                metadata_path,
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )
        except OSError as error:
            if raw_path is not None:
                raw_path.unlink(missing_ok=True)
            raise EvidenceStoreError("unable to persist evidence") from error

        return EvidenceRecord(record_id, metadata_path, raw_path)

    def cleanup(self, *, now: datetime | None = None) -> CleanupResult:
        """Remove only generated artifacts whose recorded expiry has passed."""
        timestamp = self._timestamp(now)
        if not self._root.is_dir():
            return CleanupResult(raw_artifacts=0, metadata_records=0)

        raw_artifacts = 0
        metadata_records = 0
        for metadata_path in self._root.glob("*.json"):
            if not self._is_generated_metadata_path(metadata_path):
                continue
            payload = self._load_metadata(metadata_path)
            if payload is None:
                continue
            metadata_expires_at = self._parse_timestamp(payload.get("metadata_expires_at"))
            raw_expires_at = self._parse_timestamp(payload.get("raw_evidence_expires_at"))
            if metadata_expires_at is None:
                continue

            raw_path = metadata_path.with_suffix(".raw")
            if raw_expires_at is not None and raw_expires_at <= timestamp:
                raw_artifacts += int(self._unlink_if_exists(raw_path))
            if metadata_expires_at <= timestamp:
                raw_artifacts += int(self._unlink_if_exists(raw_path))
                metadata_records += int(self._unlink_if_exists(metadata_path))

        return CleanupResult(raw_artifacts=raw_artifacts, metadata_records=metadata_records)

    @staticmethod
    def _canonical_absolute_path(path: Path, label: str) -> Path:
        try:
            candidate = Path(path)
        except TypeError as error:
            raise EvidenceStoreError(f"{label} must be an absolute path") from error
        if not candidate.is_absolute():
            raise EvidenceStoreError(f"{label} must be an absolute path")
        try:
            return candidate.resolve()
        except (OSError, RuntimeError) as error:
            raise EvidenceStoreError(f"{label} cannot be resolved") from error

    @classmethod
    def _canonical_directory(cls, path: Path, label: str) -> Path:
        candidate = cls._canonical_absolute_path(path, label)
        if not candidate.is_dir():
            raise EvidenceStoreError(f"{label} must be a directory")
        return candidate

    def _assert_safe_root(self) -> None:
        try:
            self._root.relative_to(self._workspace_root)
        except ValueError:
            pass
        else:
            raise EvidenceStoreError("evidence root must be outside the workspace")

        for candidate in (self._root, *self._root.parents):
            if candidate.name == ".git" or (candidate / ".git").exists():
                raise EvidenceStoreError("evidence root must be outside a Git worktree")

    def _ensure_root(self) -> None:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not self._root.is_dir():
                raise OSError("evidence root is not a directory")
            os.chmod(self._root, 0o700)
        except OSError as error:
            raise EvidenceStoreError("unable to prepare evidence root") from error

    def _serialize_result(self, result: CapabilityResult) -> dict[str, object]:
        if not isinstance(result, CapabilityResult):
            raise EvidenceStoreError("results must contain CapabilityResult instances")
        provenance = None
        if result.provenance is not None:
            provenance = {
                "capability_name": self._required_string(
                    result.provenance.capability_name, "capability name"
                ),
                "capability_version": self._required_string(
                    result.provenance.capability_version, "capability version"
                ),
            }
        serialized: dict[str, object] = {
            "status": result.status.value,
            "error_code": result.error_code.value if result.error_code else None,
            "provenance": provenance,
        }
        if result.control_evidence:
            serialized["control_evidence"] = [
                self._serialize_control_evidence(item)
                for item in result.control_evidence
            ]
            serialized["findings"] = []
        else:
            serialized["findings"] = [
                self._serialize_finding(finding) for finding in result.findings
            ]
        return serialized

    def _serialize_control_evidence(self, evidence: ControlEvidence) -> dict[str, object]:
        serialized: dict[str, object] = {
            "rule_id": self._required_string(evidence.rule_id, "control rule ID"),
            "category": self._required_string(evidence.category, "control category"),
            "confidence": evidence.confidence,
        }
        if evidence.identifier is not None:
            serialized["identifier"] = self._required_string(
                evidence.identifier, "control identifier"
            )
        if evidence.metrics:
            serialized["metrics"] = dict(evidence.metrics)
        return serialized

    def _serialize_finding(self, finding: Finding) -> dict[str, object]:
        if not isinstance(finding, Finding):
            raise EvidenceStoreError("results must contain normalized findings")
        line = finding.line
        if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
            raise EvidenceStoreError("finding line must be a positive integer or None")
        return {
            "source": self._required_string(finding.source, "finding source"),
            "file_path": self._required_string(finding.file_path, "finding file path"),
            "line": line,
            "severity": self._required_string(finding.severity, "finding severity"),
            "rule_id": self._required_string(finding.rule_id, "finding rule ID"),
            "cwe": finding.cwe if isinstance(finding.cwe, str) else None,
        }

    @staticmethod
    def _required_string(value: object, label: str) -> str:
        if not isinstance(value, str) or not value:
            raise EvidenceStoreError(f"{label} must be a non-empty string")
        return value

    def _atomic_write(self, destination: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self._root, prefix=".pending-", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                descriptor = -1
                file.write(content)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_path, destination)
            os.chmod(destination, 0o600)
        except OSError:
            if descriptor != -1:
                os.close(descriptor)
            raise
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _timestamp(value: datetime | None) -> datetime:
        timestamp = value or datetime.now(timezone.utc)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise EvidenceStoreError("timestamps must be timezone-aware")
        return timestamp.astimezone(timezone.utc)

    def _is_generated_metadata_path(self, path: Path) -> bool:
        if path.parent != self._root or path.suffix != ".json":
            return False
        try:
            record_id = uuid.UUID(hex=path.stem)
        except ValueError:
            return False
        return record_id.hex == path.stem and record_id.version == 4

    @staticmethod
    def _load_metadata(path: Path) -> dict[str, object] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
            return None
        return payload

    @staticmethod
    def _parse_timestamp(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return None
        return timestamp.astimezone(timezone.utc)

    @staticmethod
    def _unlink_if_exists(path: Path) -> bool:
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        return True
