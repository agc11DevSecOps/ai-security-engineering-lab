"""Advisory trust scoring from approved, versioned historical evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from core.consolidator import ConsolidatedFinding


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CALIBRATION = PROJECT_ROOT / "calibrations" / "trust-score-hybrid-v2.json"


@dataclass(frozen=True)
class TrustScore:
    """Non-decision evidence attached to one consolidated finding."""

    status: str
    score: float | None
    reason: str | None
    calibration_release: str | None
    dataset_version: str | None
    source_profiles: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "score": self.score,
            "reason": self.reason,
            "calibration_release": self.calibration_release,
            "dataset_version": self.dataset_version,
            "source_profiles": list(self.source_profiles),
        }


class CalibrationUnavailable(Exception):
    """The release cannot safely score the requested evidence."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TrustCalibration:
    """Validated, immutable calibration release; never controlled by producers."""

    def __init__(self, path: Path = DEFAULT_CALIBRATION) -> None:
        self.path = path
        self.data = self._load()

    def _load(self) -> dict[str, object]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as error:
            raise CalibrationUnavailable("calibration-release-unavailable") from error

        if data.get("status") != "approved":
            raise CalibrationUnavailable("calibration-not-approved")
        approval = data.get("approval")
        if not isinstance(approval, dict) or not all(
            isinstance(approval.get(key), str) and approval[key]
            for key in ("reviewer", "approval_id", "release_id", "approved_at")
        ):
            raise CalibrationUnavailable("calibration-approval-incomplete")

        for evidence_key in ("ground_truth", "scorecard"):
            evidence = data.get(evidence_key)
            if not isinstance(evidence, dict):
                raise CalibrationUnavailable("calibration-evidence-incomplete")
            relative_path = evidence.get("path")
            expected_hash = evidence.get("sha256")
            if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
                raise CalibrationUnavailable("calibration-evidence-incomplete")
            artifact = PROJECT_ROOT.parent / relative_path
            if not artifact.is_file() or _sha256(artifact) != expected_hash:
                raise CalibrationUnavailable("calibration-evidence-stale")

        method = data.get("method")
        if not isinstance(method, dict) or method.get("id") != "hybrid-source-agreement-v1":
            raise CalibrationUnavailable("calibration-method-unsupported")
        return data

    @property
    def release_id(self) -> str:
        return self.data["approval"]["release_id"]  # type: ignore[index]

    @property
    def dataset_version(self) -> str:
        return self.data["ground_truth"]["sha256"]  # type: ignore[index]

    def profile(self, source: str, category: str) -> dict[str, object] | None:
        profiles = self.data.get("profiles")
        if not isinstance(profiles, list):
            return None
        for profile in profiles:
            if (
                isinstance(profile, dict)
                and profile.get("source") == source
                and profile.get("category") == category
            ):
                return profile
        return None


def score_finding(
    finding: ConsolidatedFinding,
    calibration: TrustCalibration | None = None,
) -> TrustScore:
    """Return advisory evidence for one finding without changing its verdict."""
    try:
        active = calibration or TrustCalibration()
    except CalibrationUnavailable as error:
        return TrustScore(
            status="calibration-unavailable",
            score=None,
            reason=str(error),
            calibration_release=None,
            dataset_version=None,
            source_profiles=(),
        )

    if len(finding.categories) != 1:
        return TrustScore(
            status="calibration-unavailable",
            score=None,
            reason="category-disagreement",
            calibration_release=active.release_id,
            dataset_version=active.dataset_version,
            source_profiles=(),
        )

    candidates: list[tuple[str, dict[str, object]]] = []
    for source in finding.sources:
        for category in finding.categories:
            profile = active.profile(source, category)
            if profile is not None:
                candidates.append((f"{source}:{category}", profile))

    if not candidates:
        return TrustScore(
            status="calibration-unavailable",
            score=None,
            reason="no-calibrated-source-category",
            calibration_release=active.release_id,
            dataset_version=active.dataset_version,
            source_profiles=(),
        )

    # Profiles are empirical precision estimates. Agreement only compounds
    # estimates from declared independent sources; it never suppresses a finding.
    independent: dict[str, tuple[str, float]] = {}
    for name, profile in candidates:
        group = profile.get("independence_group")
        precision = profile.get("precision")
        if not isinstance(group, str) or not isinstance(precision, (int, float)):
            continue
        independent.setdefault(group, (name, float(precision)))
    if not independent:
        return TrustScore(
            status="calibration-unavailable",
            score=None,
            reason="calibration-profile-invalid",
            calibration_release=active.release_id,
            dataset_version=active.dataset_version,
            source_profiles=(),
        )

    values = tuple(independent.values())
    score = values[0][1] if len(values) == 1 else 1.0
    if len(values) > 1:
        for _, precision in values:
            score *= 1.0 - precision
        score = 1.0 - score

    return TrustScore(
        status="calibrated-advisory",
        score=round(score, 4),
        reason=None,
        calibration_release=active.release_id,
        dataset_version=active.dataset_version,
        source_profiles=tuple(name for name, _ in values),
    )
