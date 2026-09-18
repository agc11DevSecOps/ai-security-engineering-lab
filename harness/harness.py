"""Local-only command line entry point for the AI-security harness."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from capabilities.bandit_capability import BanditCapability
from capabilities.garak_capability import GarakCapability
from capabilities.prompt_guard_capability import PromptGuardCapability
from capabilities.presidio_capability import PresidioCapability
from capabilities.vulnhuntr_capability import VulnhuntrCapability
from core.capability import (
    CapabilityProvenance,
    CapabilityRequest,
    CapabilityResult,
    CapabilityStatus,
    ControlEvidence,
    MAX_MESSAGE_BYTES,
    TaskType,
)
from core.consolidator import ConsolidatedFinding, consolidate
from core.evidence_store import EvidenceStore, EvidenceStoreError
from core.finding import Finding
from core.router import Router
from core.trust_score import score_finding


SAFE_EXTRA_FIELDS = frozenset({"test_name", "more_info"})
STATE_DIR_NAME = "ai-security-harness"
ANALYSIS_PROFILES = frozenset({"fast", "deep"})


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("must be an absolute path")
    return path


def _timeout_seconds(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 1 <= timeout <= 3_600:
        raise argparse.ArgumentTypeError("must be between 1 and 3600")
    return timeout


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run local AI-security capabilities.")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run capabilities for one target")
    run.add_argument("--task", choices=[task.value for task in TaskType], required=True)
    run.add_argument("--target", type=_absolute_path)
    run.add_argument("--workspace-root", type=_absolute_path, required=True)
    run.add_argument(
        "--message-stdin",
        action="store_true",
        help="read the input_guard message from standard input",
    )
    run.add_argument("--timeout-seconds", type=_timeout_seconds, default=300)
    run.add_argument(
        "--analysis-profile",
        choices=sorted(ANALYSIS_PROFILES),
        default="fast",
        help="fast runs deterministic analysis; deep adds advisory local LLM analysis",
    )
    run.add_argument(
        "--campaign-manifest",
        type=_absolute_path,
        help="approved campaign manifest required for llm_red_team",
    )
    return parser


def _serialize_finding(finding: Finding) -> dict[str, object]:
    """Emit the reviewed normalized schema, never arbitrary adapter metadata."""
    extra = {
        key: value
        for key, value in finding.extra.items()
        if key in SAFE_EXTRA_FIELDS and isinstance(value, str)
    }
    return {
        "source": finding.source,
        "file_path": finding.file_path,
        "line": finding.line,
        "severity": finding.severity,
        "rule_id": finding.rule_id,
        "description": finding.description,
        "confidence": finding.confidence,
        "cwe": finding.cwe,
        "poc": finding.poc,
        "extra": extra,
    }


def _serialize_provenance(
    provenance: CapabilityProvenance | None,
) -> dict[str, object] | None:
    if provenance is None:
        return None
    return {
        "capability_name": provenance.capability_name,
        "capability_version": provenance.capability_version,
        "target": str(provenance.target) if provenance.target is not None else None,
    }


def _serialize_control_evidence(evidence: ControlEvidence) -> dict[str, object]:
    """Emit reviewed control evidence without a message or enforcement field."""
    serialized: dict[str, object] = {
        "rule_id": evidence.rule_id,
        "category": evidence.category,
        "confidence": evidence.confidence,
    }
    if evidence.identifier is not None:
        serialized["identifier"] = evidence.identifier
    if evidence.metrics:
        serialized["metrics"] = dict(evidence.metrics)
    return serialized


def _serialize_result(result: CapabilityResult) -> dict[str, object]:
    serialized: dict[str, object] = {
        "status": result.status.value,
        "error_code": result.error_code.value if result.error_code else None,
        "provenance": _serialize_provenance(result.provenance),
    }
    if result.control_evidence:
        serialized["findings"] = []
        serialized["control_evidence"] = [
            _serialize_control_evidence(item) for item in result.control_evidence
        ]
    else:
        serialized["findings"] = [
            _serialize_finding(finding) for finding in result.findings
        ]
    return serialized


def _serialize_consolidated(entry: ConsolidatedFinding) -> dict[str, object]:
    """Surface the consolidation decision without copying source findings."""
    return {
        "file_path": entry.file_path,
        "line": entry.line,
        "status": entry.status.value,
        "sources": list(entry.sources),
        "categories": list(entry.categories),
        "trust_score": score_finding(entry).as_dict(),
    }


def resolve_state_root(env: Mapping[str, str]) -> Path:
    """Resolve the user-private state root from XDG, with the spec fallback."""
    xdg_state_home = env.get("XDG_STATE_HOME")
    if xdg_state_home:
        candidate = Path(xdg_state_home)
        if candidate.is_absolute():
            return candidate / STATE_DIR_NAME
    return Path.home() / ".local" / "state" / STATE_DIR_NAME


def _persist_results(
    request: CapabilityRequest,
    results: tuple[CapabilityResult, ...],
    evidence_store: EvidenceStore | None,
) -> dict[str, str]:
    """Persist redacted run metadata without exposing its location."""
    try:
        store = evidence_store or EvidenceStore(
            resolve_state_root(os.environ), request.workspace_root
        )
        record = store.write(request, results)
    except EvidenceStoreError as error:
        return {"status": "failed", "reason": str(error)}
    return {"status": "written", "record_id": record.record_id}


def main(
    argv: Sequence[str] | None = None,
    *,
    router: Router | None = None,
    output: TextIO | None = None,
    input: TextIO | None = None,
    evidence_store: EvidenceStore | None = None,
) -> int:
    """Run the requested local scan and return a process-compatible exit code."""
    parser = _parser()
    arguments = parser.parse_args(argv)
    task = TaskType(arguments.task)
    campaign_manifest = None
    if task is TaskType.CODE_ANALYSIS:
        if arguments.target is None:
            parser.error("--target is required for code_analysis")
        if arguments.message_stdin:
            parser.error("--message-stdin is not supported for code_analysis")
        target = arguments.target
        message = None
    elif task is TaskType.INPUT_GUARD:
        if arguments.analysis_profile != "fast":
            parser.error("--analysis-profile is supported only for code_analysis")
        if not arguments.message_stdin:
            parser.error("--message-stdin is required for input_guard")
        if arguments.target is not None:
            parser.error("--target is not supported for input_guard")
        target = None
        # Keep untrusted messages out of process arguments and shell history.
        message = (input or sys.stdin).read(MAX_MESSAGE_BYTES + 1)
    else:
        if arguments.analysis_profile != "fast":
            parser.error("--analysis-profile is supported only for code_analysis")
        if arguments.target is not None:
            parser.error("--target is not supported for llm_red_team")
        if arguments.message_stdin:
            parser.error("--message-stdin is not supported for llm_red_team")
        if arguments.campaign_manifest is None:
            parser.error("--campaign-manifest is required for llm_red_team")
        target = None
        message = None
        campaign_manifest = arguments.campaign_manifest
    request = CapabilityRequest(
        task_type=task,
        workspace_root=arguments.workspace_root,
        target=target,
        message=message,
        campaign_manifest=campaign_manifest,
        timeout_seconds=arguments.timeout_seconds,
    )
    if router is not None:
        active_router = router
    else:
        capabilities = [
            BanditCapability(),
            PromptGuardCapability(),
            PresidioCapability(),
            GarakCapability(),
        ]
        if task is TaskType.CODE_ANALYSIS and arguments.analysis_profile == "deep":
            capabilities.append(VulnhuntrCapability())
        active_router = Router(capabilities)
    results = active_router.run(request)
    consolidated = consolidate(
        finding for result in results for finding in result.findings
    )
    persistence = _persist_results(request, results, evidence_store)
    report = {
        "task": request.task_type.value,
        "target": str(request.target) if request.target is not None else None,
        "workspace_root": str(request.workspace_root),
        "results": [_serialize_result(result) for result in results],
        "consolidated": [_serialize_consolidated(entry) for entry in consolidated],
        "persistence": persistence,
    }
    json.dump(report, output or sys.stdout, sort_keys=True)
    (output or sys.stdout).write("\n")
    completed = all(
        result.status is CapabilityStatus.COMPLETED for result in results
    )
    return int(not completed or persistence["status"] != "written")


if __name__ == "__main__":
    raise SystemExit(main())
