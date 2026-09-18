#!/usr/bin/env python3
"""Measure the bounded harness profiles against the synthetic local-flow oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path


PHASE_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = (
    PHASE_ROOT.parent / "labs" / "06-code-security-evaluation" / "local-flow-benchmark"
)
FIXTURES_ROOT = EVALUATION_ROOT / "fixtures"
ORACLE_PATH = EVALUATION_ROOT / "ground_truth.json"
ISOLATED_SCORECARD_PATH = EVALUATION_ROOT / "reports" / "scorecard.json"
OUTPUT_PATH = PHASE_ROOT / "calibrations" / "evidence" / "harness-value-measurement.json"
CATEGORY_EQUIVALENCE = {"B608": "SQLI"}


def _read_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _category(finding: Mapping[str, object]) -> str | None:
    rule_id = finding.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        return None
    return CATEGORY_EQUIVALENCE.get(rule_id.upper(), rule_id.upper())


def _matches_expected(finding: Mapping[str, object], case: Mapping[str, object]) -> bool:
    category = _category(finding)
    file_path = finding.get("file_path")
    line = finding.get("line")
    if not isinstance(category, str) or not isinstance(file_path, str):
        return False
    expected_findings = case.get("expected_findings")
    if not isinstance(expected_findings, list):
        return False
    for expected in expected_findings:
        if not isinstance(expected, Mapping) or expected.get("category") != category:
            continue
        for location in expected.get("accepted_detection_locations", []):
            if (
                isinstance(location, Mapping)
                and location.get("path") == file_path
                and location.get("line") == line
            ):
                return True
    return False


def score_profile(
    runs: Sequence[Mapping[str, object]], oracle: Mapping[str, object], profile: str
) -> dict[str, int | None]:
    """Score complete profile runs; incomplete runs remain unavailable."""
    scores: dict[str, int | None] = {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "unavailable": 0,
    }
    cases = oracle.get("cases")
    if not isinstance(cases, Mapping):
        raise ValueError("oracle must contain cases")
    for run in runs:
        if run.get("profile") != profile:
            continue
        case_name = run.get("case")
        case = cases.get(case_name) if isinstance(case_name, str) else None
        if not isinstance(case, Mapping):
            raise ValueError("run references an unknown case")
        if run.get("status") != "completed":
            scores["unavailable"] = int(scores["unavailable"] or 0) + 1
            continue
        findings = run.get("findings")
        if not isinstance(findings, list):
            raise ValueError("completed run must include findings")
        vulnerable = case.get("verdict") == "vulnerable"
        matched = any(
            isinstance(finding, Mapping) and _matches_expected(finding, case)
            for finding in findings
        )
        if vulnerable and matched:
            scores["tp"] = int(scores["tp"] or 0) + 1
        elif vulnerable:
            scores["fn"] = int(scores["fn"] or 0) + 1
        elif findings:
            scores["fp"] = int(scores["fp"] or 0) + 1
        else:
            scores["tn"] = int(scores["tn"] or 0) + 1
    tp, fp, fn = (int(scores[key] or 0) for key in ("tp", "fp", "fn"))
    scores["precision"] = round(tp / (tp + fp), 4) if tp + fp else None
    scores["recall"] = round(tp / (tp + fn), 4) if tp + fn else None
    return scores


def _deep_signal_counts(runs: Sequence[Mapping[str, object]]) -> dict[str, int]:
    counts = {"corroborated": 0, "uncorroborated": 0, "disagreement": 0}
    for run in runs:
        if run.get("profile") != "deep":
            continue
        for entry in run.get("consolidated", []):
            if not isinstance(entry, Mapping) or "vulnhuntr" not in entry.get("sources", []):
                continue
            status = entry.get("status")
            if status == "agreement":
                counts["corroborated"] += 1
            elif status == "disagreement":
                counts["disagreement"] += 1
            else:
                counts["uncorroborated"] += 1
    return counts


def _run_profile(case_name: str, profile: str, timeout_seconds: int) -> dict[str, object]:
    target = (FIXTURES_ROOT / case_name).resolve()
    command = [
        sys.executable,
        str(PHASE_ROOT / "harness.py"),
        "run",
        "--task",
        "code_analysis",
        "--analysis-profile",
        profile,
        "--timeout-seconds",
        str(timeout_seconds),
        "--target",
        str(target),
        "--workspace-root",
        str(EVALUATION_ROOT),
    ]
    environment = {
        **os.environ,
        "NO_PROXY": "*",
        "no_proxy": "*",
        "http_proxy": "",
        "https_proxy": "",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
    }
    started = time.monotonic()
    completed = subprocess.run(  # nosec B603
        command,
        capture_output=True,
        check=False,
        cwd=str(PHASE_ROOT),
        env=environment,
        text=True,
    )
    elapsed_seconds = round(time.monotonic() - started, 3)
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {
            "case": case_name,
            "profile": profile,
            "elapsed_seconds": elapsed_seconds,
            "exit_status": completed.returncode,
            "status": "invalid_harness_output",
            "findings": [],
            "consolidated": [],
        }
    results = report.get("results") if isinstance(report, Mapping) else None
    if not isinstance(results, list):
        raise ValueError("harness report must include results")
    findings = [
        finding
        for result in results
        if isinstance(result, Mapping)
        for finding in result.get("findings", [])
        if isinstance(finding, Mapping)
    ]
    complete = completed.returncode == 0 and all(
        isinstance(result, Mapping) and result.get("status") == "completed"
        for result in results
    )
    return {
        "case": case_name,
        "profile": profile,
        "elapsed_seconds": elapsed_seconds,
        "exit_status": completed.returncode,
        "status": "completed" if complete else "incomplete",
        "findings": findings,
        "consolidated": report.get("consolidated", []),
        "capabilities": [
            {
                "name": result.get("provenance", {}).get("capability_name"),
                "status": result.get("status"),
                "error_code": result.get("error_code"),
            }
            for result in results
            if isinstance(result, Mapping)
        ],
    }


def _timeout_seconds(value: str) -> int:
    try:
        timeout_seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if not 1 <= timeout_seconds <= 600:
        raise argparse.ArgumentTypeError("must be between 1 and 600")
    return timeout_seconds


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure the bounded harness against the synthetic Fase 4f oracle."
    )
    parser.add_argument(
        "--profile",
        choices=("fast", "deep"),
        action="append",
        dest="profiles",
        help="profile to run; defaults to the deterministic fast profile only",
    )
    parser.add_argument(
        "--case",
        action="append",
        dest="cases",
        help="oracle case to run; required for the resource-intensive deep profile",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=_timeout_seconds,
        default=90,
        help="per-file timeout, limited to 600 seconds (default: 90)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="reuse compatible completed checkpoints from the evidence JSON",
    )
    return parser


def _load_resumable_runs(oracle_sha256: str) -> list[dict[str, object]]:
    try:
        saved = _read_json(OUTPUT_PATH)
    except ValueError:
        return []
    corpus = saved.get("corpus")
    runs = saved.get("runs")
    if not isinstance(corpus, Mapping) or corpus.get("oracle_sha256") != oracle_sha256:
        return []
    if not isinstance(runs, list) or not all(isinstance(run, Mapping) for run in runs):
        return []
    return [dict(run) for run in runs]


def _report(
    *,
    oracle: Mapping[str, object],
    oracle_sha256: str,
    profiles: Sequence[str],
    timeout_seconds: int,
    runs: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "corpus": {
            "name": "local-flow-benchmark-v7",
            "oracle_sha256": oracle_sha256,
            "cases": len(oracle["cases"]),
        },
        "configuration": {
            "model": "qwen2.5-coder:7b-instruct",
            "profiles": list(profiles),
            "timeout_seconds_per_file": timeout_seconds,
        },
        "isolated_source_scorecard": _read_json(ISOLATED_SCORECARD_PATH),
        "runs": list(runs),
        "profile_scorecard": {
            profile: score_profile(runs, oracle, profile) for profile in profiles
        },
        "deep_llm_signals": _deep_signal_counts(runs),
    }


def _write_checkpoint(report: Mapping[str, object]) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{OUTPUT_PATH.name}.", suffix=".tmp", dir=OUTPUT_PATH.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
            json.dump(report, temporary_file, indent=2, sort_keys=True)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, OUTPUT_PATH)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    profiles = tuple(dict.fromkeys(arguments.profiles or ("fast",)))
    oracle = _read_json(ORACLE_PATH)
    cases = oracle.get("cases")
    if not isinstance(cases, Mapping):
        raise SystemExit("oracle must contain cases")
    selected_cases = tuple(arguments.cases or sorted(cases))
    unknown_cases = sorted(set(selected_cases).difference(cases))
    if unknown_cases:
        _parser().error(f"unknown oracle case(s): {', '.join(unknown_cases)}")
    if "deep" in profiles and not arguments.cases:
        _parser().error("--profile deep requires one or more explicit --case values")

    oracle_sha256 = _sha256(ORACLE_PATH)
    runs = _load_resumable_runs(oracle_sha256) if arguments.resume else []
    completed_pairs = {
        (run.get("case"), run.get("profile"))
        for run in runs
        if isinstance(run.get("case"), str) and isinstance(run.get("profile"), str)
    }
    for profile in profiles:
        for case_name in selected_cases:
            if (case_name, profile) in completed_pairs:
                continue
            runs.append(
                _run_profile(case_name, profile, timeout_seconds=arguments.timeout_seconds)
            )
            _write_checkpoint(
                _report(
                    oracle=oracle,
                    oracle_sha256=oracle_sha256,
                    profiles=profiles,
                    timeout_seconds=arguments.timeout_seconds,
                    runs=runs,
                )
            )
    report = _report(
        oracle=oracle,
        oracle_sha256=oracle_sha256,
        profiles=profiles,
        timeout_seconds=arguments.timeout_seconds,
        runs=runs,
    )
    _write_checkpoint(report)
    print(json.dumps(report["profile_scorecard"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
