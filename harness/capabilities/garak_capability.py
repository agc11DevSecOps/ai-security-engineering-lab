"""Gated Garak capability for the approved synthetic staging campaign."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from core.capability import (
    Capability,
    CapabilityRequest,
    CapabilityResult,
    ErrorCode,
    ControlEvidence,
    TaskType,
)


def build_staging_runner(env: object | None = None) -> "StagingGarakRunner":
    """Resolve the fixed reviewed execution pair; never inherit CLI paths."""
    environment = os.environ if env is None else env
    executable = environment.get("GARAK_BIN")
    if not executable:
        raise ValueError("GARAK_BIN must name the reviewed absolute Garak executable")
    from core.garak_campaign import StagingGarakRunner, require_approved_staging_config
    return StagingGarakRunner(Path(executable), require_approved_staging_config())


class GarakCapability(Capability):
    """Run only the approved synthetic Garak campaign and return control evidence."""

    name = "garak"
    version = "0.16.0-staging-smoke"
    supported_task_types = frozenset({TaskType.LLM_RED_TEAM})

    def __init__(
        self,
        runner_factory: Callable[..., "StagingGarakRunner"] = build_staging_runner,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._runner_factory = runner_factory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _run(self, request: CapabilityRequest) -> CapabilityResult:
        if request.campaign_manifest is None:
            return CapabilityResult.failed(ErrorCode.MISSING_CAMPAIGN_MANIFEST)
        try:
            from core.garak_campaign import load_approved_staging_campaign
            campaign = load_approved_staging_campaign(
                Path(request.campaign_manifest), now=self._clock()
            )
        except Exception:
            return CapabilityResult.failed(ErrorCode.INVALID_CAMPAIGN_MANIFEST)
        try:
            runner = self._runner_factory()
        except (OSError, ValueError):
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)

        outcome = runner.run(Path(request.campaign_manifest))
        return self._to_result(outcome, campaign.campaign_id, campaign.probes[0])

    def _to_result(
        self,
        outcome,
        campaign_id: str,
        probe: str,
    ) -> CapabilityResult:
        if outcome.status.name == "COMPLETED" and outcome.summary is not None:
            evidence = ControlEvidence(
                rule_id=f"GARAK_{probe.upper()}",
                category="garak_evaluation",
                identifier=campaign_id,
                metrics=(
                    ("attempt_count", outcome.summary.attempt_count),
                    ("failure_count", outcome.summary.failure_count),
                    ("hit_count", outcome.summary.hit_count),
                ),
            )
            return CapabilityResult.observed((evidence,))
        if outcome.error is not None and outcome.error.value == "timeout":
            return CapabilityResult.incomplete(ErrorCode.TOOL_TIMEOUT)
        if outcome.error is not None and outcome.error.value == "executable_unavailable":
            return CapabilityResult.incomplete(ErrorCode.TOOL_UNAVAILABLE)
        return CapabilityResult.incomplete(ErrorCode.TOOL_FAILED)
