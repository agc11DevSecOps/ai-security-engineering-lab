"""Validated, deny-by-default Garak campaign manifests."""

from __future__ import annotations

import json
import re
import hashlib
# The invocation below uses a fixed executable and an argv list without a shell.
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path


_CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_OFFLINE_GENERATORS = frozenset({"test.Blank", "test.Repeat"})
_OFFLINE_PROBES = frozenset({"encoding.InjectBase64"})
_STAGING_GENERATOR = "rest.RestGenerator"
_STAGING_PROBES = frozenset({"encoding.InjectBase64"})
_MAX_SUMMARY_LINE_BYTES = 1_024
PROJECT_ROOT = Path(__file__).resolve().parents[1]
APPROVED_STAGING_MANIFEST = PROJECT_ROOT / "campaigns" / "garak-synthetic-staging-template.json"
APPROVED_STAGING_CONFIG = PROJECT_ROOT / "config" / "garak-synthetic-staging-smoke.json"
APPROVED_STAGING_MANIFEST_SHA256 = "7185e49c4144e8fe422992c69ee66b6ec39736c98b59593b893a7d8033368072"
APPROVED_STAGING_CONFIG_SHA256 = "82b35eb7f5c688baaf3b0e6bd28735556e07cd9c368ff27de0780015af675b47"
ProcessRunner = Callable[..., subprocess.CompletedProcess[object]]
CampaignLoader = Callable[[Path], "StagingCampaign"]


class CampaignManifestError(ValueError):
    """Manifest is incomplete, unsafe, or outside the offline contract."""


@dataclass(frozen=True)
class GarakCampaign:
    campaign_id: str
    reviewer: str
    generator: str
    probes: tuple[str, ...]
    request_budget: int
    timeout_seconds: int


@dataclass(frozen=True)
class StagingTarget:
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class StagingCampaign:
    campaign_id: str
    owner: str
    reviewer: str
    target: StagingTarget
    generator: str
    probes: tuple[str, ...]
    request_budget: int
    timeout_seconds: int
    approved_at: datetime
    window_minutes: int


class GarakRunStatus(str, Enum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"


class GarakRunError(str, Enum):
    EXECUTABLE_UNAVAILABLE = "executable_unavailable"
    TIMEOUT = "timeout"
    BAD_EXIT = "bad_exit"
    INVALID_REPORT = "invalid_report"


@dataclass(frozen=True)
class GarakReportSummary:
    attempt_count: int
    failure_count: int
    hit_count: int

    def __post_init__(self) -> None:
        counts = (self.attempt_count, self.failure_count, self.hit_count)
        if not all(isinstance(count, int) and not isinstance(count, bool) for count in counts):
            raise TypeError("Garak summary counts must be integers")
        if any(count < 0 for count in counts):
            raise ValueError("Garak summary counts must be non-negative")
        if self.failure_count > self.attempt_count or self.hit_count > self.attempt_count:
            raise ValueError("Garak summary counts cannot exceed attempts")


@dataclass(frozen=True)
class GarakRunResult:
    status: GarakRunStatus
    summary: GarakReportSummary | None = None
    error: GarakRunError | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, GarakRunStatus):
            raise TypeError("status must be a GarakRunStatus")
        if self.summary is not None and not isinstance(self.summary, GarakReportSummary):
            raise TypeError("summary must be a GarakReportSummary or None")
        if self.error is not None and not isinstance(self.error, GarakRunError):
            raise TypeError("error must be a GarakRunError or None")
        if self.status is GarakRunStatus.COMPLETED:
            if self.summary is None or self.error is not None:
                raise ValueError("completed Garak runs require only a summary")
        elif self.summary is not None or self.error is None:
            raise ValueError("incomplete Garak runs require only an error")

    @classmethod
    def completed(cls, summary: GarakReportSummary) -> GarakRunResult:
        return cls(status=GarakRunStatus.COMPLETED, summary=summary)

    @classmethod
    def incomplete(cls, error: GarakRunError) -> GarakRunResult:
        return cls(status=GarakRunStatus.INCOMPLETE, error=error)


def load_offline_campaign(path: Path) -> GarakCampaign:
    """Load a reviewed offline-only campaign without allowing a target or network."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignManifestError("campaign-manifest-unavailable") from error
    if not isinstance(data, dict):
        raise CampaignManifestError("campaign-manifest-invalid")
    if data.get("schema_version") != 1 or data.get("status") != "approved-offline":
        raise CampaignManifestError("campaign-not-approved-offline")

    campaign_id = _string(data, "campaign_id")
    reviewer = _string(data, "reviewer")
    generator = _string(data, "generator")
    if not _CAMPAIGN_ID.fullmatch(campaign_id) or generator not in _OFFLINE_GENERATORS:
        raise CampaignManifestError("campaign-manifest-invalid")
    if data.get("mode") != "offline" or data.get("target") is not None:
        raise CampaignManifestError("campaign-network-not-allowed")
    if data.get("network_authorization") is not None or data.get("allow_raw_evidence") is not False:
        raise CampaignManifestError("campaign-network-not-allowed")
    if data.get("concurrency") != 1:
        raise CampaignManifestError("campaign-manifest-invalid")

    probes = data.get("probes")
    if not isinstance(probes, list) or not probes or not all(probe in _OFFLINE_PROBES for probe in probes):
        raise CampaignManifestError("campaign-manifest-invalid")
    request_budget = _bounded_int(data, "request_budget", 1, 100)
    if len(probes) > request_budget:
        raise CampaignManifestError("campaign-manifest-invalid")
    timeout_seconds = _bounded_int(data, "timeout_seconds", 1, 3_600)
    return GarakCampaign(
        campaign_id=campaign_id,
        reviewer=reviewer,
        generator=generator,
        probes=tuple(probes),
        request_budget=request_budget,
        timeout_seconds=timeout_seconds,
    )


def load_staging_campaign(path: Path) -> StagingCampaign:
    """Load the exact approved synthetic staging campaign; reject everything else.

    Only the reviewed loopback smoke manifest may enable network access. The
    target must match the allowed tuple exactly and every other field must be the
    approved value. This loader never reads a user-controlled URL for execution.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignManifestError("campaign-manifest-unavailable") from error
    if not isinstance(data, dict):
        raise CampaignManifestError("campaign-manifest-invalid")
    if data.get("schema_version") != 1 or data.get("status") != "approved":
        raise CampaignManifestError("campaign-not-approved")
    if data.get("network_authorization") is not True:
        raise CampaignManifestError("campaign-network-not-authorized")
    if data.get("allow_raw_evidence") is not False:
        raise CampaignManifestError("campaign-raw-evidence-not-allowed")
    if data.get("concurrency") != 1:
        raise CampaignManifestError("campaign-manifest-invalid")
    if data.get("credentials") != "none":
        raise CampaignManifestError("campaign-credentials-not-allowed")

    campaign_id = _string(data, "campaign_id")
    owner = _string(data, "owner")
    reviewer = _string(data, "reviewer")
    generator = _string(data, "generator")
    if not _CAMPAIGN_ID.fullmatch(campaign_id) or generator != _STAGING_GENERATOR:
        raise CampaignManifestError("campaign-manifest-invalid")

    target = data.get("target")
    if not isinstance(target, dict):
        raise CampaignManifestError("campaign-manifest-invalid")
    allowed_target = ("http", "127.0.0.1", 8088, "/chat")
    actual_target = (
        target.get("scheme"),
        target.get("host"),
        target.get("port"),
        target.get("path"),
    )
    if actual_target != allowed_target:
        raise CampaignManifestError("campaign-target-not-allowed")

    probes = data.get("probes")
    if not isinstance(probes, list) or not probes or set(probes) != _STAGING_PROBES:
        raise CampaignManifestError("campaign-manifest-invalid")
    request_budget = _bounded_int(data, "request_budget", 1, 100)
    timeout_seconds = _bounded_int(data, "timeout_seconds", 1, 3_600)
    window_minutes = _bounded_int(data, "window_minutes", 1, 60)
    approved_at = _timestamp(data, "approved_at")
    approval = data.get("approval")
    if not isinstance(approval, dict) or not all(
        isinstance(approval.get(key), str) and approval[key].strip()
        for key in ("c1", "c2")
    ):
        raise CampaignManifestError("campaign-approval-incomplete")
    return StagingCampaign(
        campaign_id=campaign_id,
        owner=owner,
        reviewer=reviewer,
        target=StagingTarget(scheme="http", host="127.0.0.1", port=8088, path="/chat"),
        generator=generator,
        probes=tuple(probes),
        request_budget=request_budget,
        timeout_seconds=timeout_seconds,
        approved_at=approved_at,
        window_minutes=window_minutes,
    )


def load_approved_staging_campaign(
    path: Path, *, now: datetime | None = None
) -> StagingCampaign:
    """Load only the pinned approved smoke manifest during its approved window."""
    candidate = Path(path)
    try:
        if candidate.resolve() != APPROVED_STAGING_MANIFEST.resolve():
            raise CampaignManifestError("campaign-manifest-not-approved")
    except OSError as error:
        raise CampaignManifestError("campaign-manifest-unavailable") from error
    _require_sha256(
        APPROVED_STAGING_MANIFEST,
        APPROVED_STAGING_MANIFEST_SHA256,
        "campaign-manifest-integrity-failed",
    )
    campaign = load_staging_campaign(APPROVED_STAGING_MANIFEST)
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expiry = campaign.approved_at + timedelta(minutes=campaign.window_minutes)
    if timestamp > expiry:
        raise CampaignManifestError("campaign-window-expired")
    return campaign


def require_approved_staging_config() -> Path:
    """Verify the fixed Garak configuration before permitting a staging process."""
    _require_sha256(
        APPROVED_STAGING_CONFIG,
        APPROVED_STAGING_CONFIG_SHA256,
        "campaign-config-integrity-failed",
    )
    try:
        config = json.loads(APPROVED_STAGING_CONFIG.read_text(encoding="utf-8"))
        generator = config["plugins"]["generators"]["rest"]["RestGenerator"]
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        raise CampaignManifestError("campaign-config-invalid") from error
    if not isinstance(generator, dict) or generator.get("uri") != "http://127.0.0.1:8088/chat":
        raise CampaignManifestError("campaign-config-target-not-allowed")
    if generator.get("proxies") is not None or generator.get("method") != "post":
        raise CampaignManifestError("campaign-config-invalid")
    return APPROVED_STAGING_CONFIG


def _string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise CampaignManifestError("campaign-manifest-invalid")
    return value


def _bounded_int(data: dict[str, object], key: str, minimum: int, maximum: int) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise CampaignManifestError("campaign-manifest-invalid")
    return value


def _timestamp(data: dict[str, object], key: str) -> datetime:
    value = data.get(key)
    if not isinstance(value, str):
        raise CampaignManifestError("campaign-manifest-invalid")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise CampaignManifestError("campaign-manifest-invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise CampaignManifestError("campaign-manifest-invalid")
    return timestamp.astimezone(timezone.utc)


def _require_sha256(path: Path, expected: str, error_code: str) -> None:
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CampaignManifestError(error_code) from error
    if actual != expected:
        raise CampaignManifestError(error_code)


class OfflineGarakRunner:
    """Run a reviewed test-only Garak manifest without retaining model text."""

    def __init__(
        self,
        executable: Path,
        process_runner: ProcessRunner = subprocess.run,
    ) -> None:
        executable = Path(executable)
        if not executable.is_absolute():
            raise ValueError("Garak executable must be an absolute path")
        self._executable = executable
        self._process_runner = process_runner

    def run(self, manifest_path: Path) -> GarakRunResult:
        """Revalidate a manifest, then retain and return summary counts only."""
        try:
            campaign = load_offline_campaign(manifest_path)
        except CampaignManifestError:
            return GarakRunResult.incomplete(GarakRunError.INVALID_REPORT)

        with tempfile.TemporaryDirectory(prefix="garak-offline-") as directory:
            report_prefix = Path(directory) / "report"
            argv = [
                str(self._executable),
                "--target_type",
                campaign.generator,
                "--probes",
                ",".join(campaign.probes),
                "--generations",
                str(campaign.request_budget // len(campaign.probes)),
                "--parallel_requests",
                "1",
                "--report_prefix",
                str(report_prefix),
            ]
            try:
                completed = self._process_runner(
                    argv,
                    check=False,
                    cwd=directory,
                    env=_offline_environment(directory),
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=campaign.timeout_seconds,
                )
            except (FileNotFoundError, PermissionError, OSError):
                return GarakRunResult.incomplete(GarakRunError.EXECUTABLE_UNAVAILABLE)
            except subprocess.TimeoutExpired:
                return GarakRunResult.incomplete(GarakRunError.TIMEOUT)
            if completed.returncode != 0:
                return GarakRunResult.incomplete(GarakRunError.BAD_EXIT)
            summary = _load_summary(report_prefix.with_suffix(".report.jsonl"), campaign.request_budget)
            if summary is None:
                return GarakRunResult.incomplete(GarakRunError.INVALID_REPORT)
            return GarakRunResult.completed(summary)


class StagingGarakRunner:
    """Run the exact approved synthetic staging campaign against loopback.

    The target service must already be running under the operator's control; this
    runner never starts it. It accepts only the reviewed manifest, invokes Garak
    once with the committed config, and returns filtered summary counts without
    retaining prompts or responses.
    """

    def __init__(
        self,
        executable: Path,
        config: Path,
        process_runner: ProcessRunner = subprocess.run,
        *,
        campaign_loader: CampaignLoader = load_approved_staging_campaign,
    ) -> None:
        executable = Path(executable)
        config = Path(config)
        if not executable.is_absolute():
            raise ValueError("Garak executable must be an absolute path")
        if not config.is_absolute() or not config.is_file():
            raise ValueError("Garak config must be an absolute file path")
        self._executable = executable
        self._config = config
        self._process_runner = process_runner
        self._campaign_loader = campaign_loader

    def run(self, manifest_path: Path) -> GarakRunResult:
        try:
            campaign = self._campaign_loader(manifest_path)
        except CampaignManifestError:
            return GarakRunResult.incomplete(GarakRunError.INVALID_REPORT)

        with tempfile.TemporaryDirectory(prefix="garak-staging-") as directory:
            report_prefix = Path(directory) / "report"
            argv = [
                str(self._executable),
                "--config",
                str(self._config),
                "--target_type",
                campaign.generator,
                "--spec",
                ",".join(campaign.probes),
                "--generations",
                "1",
                "--parallel_requests",
                "1",
                "--parallel_attempts",
                "1",
                "--report_prefix",
                str(report_prefix),
            ]
            try:
                completed = self._process_runner(
                    argv,
                    check=False,
                    cwd=directory,
                    env=_staging_environment(directory),
                    stderr=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    timeout=campaign.timeout_seconds,
                )
            except (FileNotFoundError, PermissionError, OSError):
                return GarakRunResult.incomplete(GarakRunError.EXECUTABLE_UNAVAILABLE)
            except subprocess.TimeoutExpired:
                return GarakRunResult.incomplete(GarakRunError.TIMEOUT)
            if completed.returncode != 0:
                return GarakRunResult.incomplete(GarakRunError.BAD_EXIT)
            summary = _load_summary(report_prefix.with_suffix(".report.jsonl"), campaign.request_budget)
            if summary is None:
                return GarakRunResult.incomplete(GarakRunError.INVALID_REPORT)
            return GarakRunResult.completed(summary)


def _staging_environment(directory: str) -> dict[str, str]:
    """Scrub credentials and proxies; keep only safe loopback-outbound defaults."""
    return {
        "HOME": directory,
        "LANG": "C.UTF-8",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
    }


def _offline_environment(directory: str) -> dict[str, str]:
    """Avoid inherited credentials and proxy settings for test generators."""
    return {
        "HOME": directory,
        "LANG": "C.UTF-8",
        "NO_PROXY": "*",
        "PATH": "/usr/bin:/bin",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "no_proxy": "*",
    }


def _load_summary(report_path: Path, request_budget: int) -> GarakReportSummary | None:
    try:
        with report_path.open("rb") as report:
            attempt_count = 0
            failure_count = 0
            completed = False
            for line in report:
                # Attempt records can contain prompts and responses; never parse them.
                if len(line) > _MAX_SUMMARY_LINE_BYTES:
                    continue
                try:
                    data = json.loads(line)
                except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                    return None
                if not isinstance(data, dict):
                    return None
                if data.get("entry_type") == "completion":
                    completed = True
                    continue
                if data.get("entry_type") != "eval":
                    continue
                if {"prompt", "outputs", "conversations"}.intersection(data):
                    return None
                counts = (data.get("total_evaluated"), data.get("fails"))
                if not all(isinstance(count, int) and not isinstance(count, bool) for count in counts):
                    return None
                attempts, failures = counts
                if attempts < 0 or failures < 0 or failures > attempts:
                    return None
                attempt_count += attempts
                failure_count += failures
    except OSError:
        return None
    if not completed or not 0 < attempt_count <= request_budget:
        return None
    return GarakReportSummary(
        attempt_count=attempt_count,
        failure_count=failure_count,
        hit_count=failure_count,
    )
