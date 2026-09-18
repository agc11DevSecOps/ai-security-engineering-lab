#!/usr/bin/env python3
"""Run the common corpus against the HTTP target and emit normalized JSONL."""
from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException
from pathlib import Path
from urllib.request import Request, urlopen
from uuid import uuid4

# Allow direct execution with `python scripts/run_target_corpus.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam_comparison.cases import (
    ATTACK_VECTORS,
    CORPUS_VERSION,
    build_common_corpus,
    build_benign_controls,
    corpus_sha256,
    select_phase_cases,
)
from redteam_comparison.oracle import evaluate, validate_target


def strict_json(text: str | bytes) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError(f"nonfinite JSON number: {value}")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid)


def call_target(url: str, message: str, timeout: float) -> dict:
    payload = json.dumps({"message": message}).encode("utf-8")
    request = Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:  # nosec B310: test URL is user-selected
        return validate_target(strict_json(response.read().decode("utf-8")))


def filter_reasons(target: dict) -> dict:
    """Keep aggregate filter evidence without retaining generated sensitive text."""
    validate_target(target)
    output_check = target["details"].get("output_check", {})
    return {
        "pii_entities": output_check.get("pii_check", {}).get("entities_found", []),
        "system_prompt_leak": output_check.get("system_prompt_leak_check", {}).get("leaked", False),
        "forbidden_keywords": output_check.get("forbidden_keywords_check", {}).get(
            "matched_keywords", []
        ),
    }


def select_cases(*, limit=0, per_vector=0, vector=None, benign_controls=0, controls_only=False):
    for name, value in (("limit", limit), ("per_vector", per_vector)):
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
    if type(controls_only) is not bool:
        raise ValueError("controls_only must be a boolean")
    if vector is not None and vector not in ATTACK_VECTORS:
        raise ValueError("unknown vector")
    controls = build_benign_controls(benign_controls)
    if limit and per_vector:
        raise ValueError("--limit and --per-vector are mutually exclusive")
    if controls_only:
        if not controls or limit or per_vector or vector is not None:
            raise ValueError("--controls-only requires controls and no attack selection")
        return controls
    cases = select_phase_cases(per_vector) if per_vector else build_common_corpus()
    if vector:
        cases = [case for case in cases if case.vector == vector]
    if limit > len(cases):
        raise ValueError(f"--limit exceeds available cases ({len(cases)})")
    return (cases[:limit] if limit else cases) + controls


def manifest_path(report: Path) -> Path:
    return report.with_name(report.name + ".manifest.json")


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_manifest(path: Path, manifest: dict, *, initial=False) -> None:
    data = (json.dumps(manifest, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()
    # Publish only complete manifests; link gives exclusive initial creation.
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if initial:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_run(report: Path) -> tuple[dict, list[dict], str]:
    """Validate v2 evidence, including partial prefixes, without repairing files."""
    path = manifest_path(report)
    if not path.exists():
        raise ValueError("missing manifest: legacy or unverified report; completeness cannot be established")
    manifest = strict_json(path.read_bytes())
    if not isinstance(manifest, dict) or manifest.get("format_version") != 2:
        raise ValueError("invalid manifest format")
    if manifest.get("corpus_version") != CORPUS_VERSION:
        raise ValueError("unsupported corpus version")
    for field in ("run_id", "tool", "url", "started_at"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            raise ValueError(f"invalid manifest {field}")
    if manifest.get("producer") != "common-http":
        raise ValueError("invalid producer (this is not a native scanner report)")
    for field in ("timeout", "pause"):
        value = manifest.get(field)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f"invalid manifest {field}")
    if manifest["timeout"] == 0:
        raise ValueError("timeout must be positive")
    selection = manifest.get("selection")
    if not isinstance(selection, dict) or set(selection) != {
        "limit", "per_vector", "vector", "benign_controls", "controls_only"
    }:
        raise ValueError("invalid manifest selection")
    cases = select_cases(**selection)
    expected_ids = [case.case_id for case in cases]
    if manifest.get("expected_ids") != expected_ids or manifest.get("corpus_sha256") != corpus_sha256(cases):
        raise ValueError("manifest expected IDs or corpus hash mismatch")
    if manifest.get("status") not in {"running", "complete"}:
        raise ValueError("invalid manifest completion status")
    data = report.read_bytes()
    if data and not data.endswith(b"\n"):
        raise ValueError("truncated report: final record lacks newline; refusing repair")
    records = []
    for index, line in enumerate(data.splitlines()):
        record = strict_json(line)
        if not isinstance(record, dict) or index >= len(cases):
            raise ValueError(f"invalid or extra record at line {index + 1}")
        for field in ("run_id", "tool", "producer", "corpus_version", "corpus_sha256"):
            if record.get(field) != manifest[field]:
                raise ValueError(f"mixed or missing {field} at line {index + 1}")
        if record.get("case") != cases[index].to_dict():
            raise ValueError(f"unexpected, duplicate, missing or reordered case at line {index + 1}")
        elapsed = record.get("elapsed_ms")
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError(f"invalid elapsed_ms at line {index + 1}")
        if not isinstance(record.get("timestamp"), str) or not record["timestamp"].strip():
            raise ValueError(f"missing timestamp at line {index + 1}")
        if "error" in record:
            if not isinstance(record["error"], str) or not record["error"].strip():
                raise ValueError("invalid error record")
            if any(field in record for field in ("verdict", "response", "blocked", "blocked_at_layer", "filter_reasons")):
                raise ValueError("error record contains success evidence")
        else:
            target = {key: record[key] for key in ("response", "blocked", "blocked_at_layer") if key in record}
            target["details"] = {}
            validate_target(target)
            if record.get("verdict") != evaluate(cases[index], target["response"], target["blocked"]).to_dict():
                raise ValueError(f"oracle verdict mismatch at line {index + 1}")
            reasons = record.get("filter_reasons")
            if not isinstance(reasons, dict) or set(reasons) != {"pii_entities", "system_prompt_leak", "forbidden_keywords"}:
                raise ValueError("invalid filter reasons")
            if type(reasons["system_prompt_leak"]) is not bool:
                raise ValueError("invalid system_prompt_leak")
            for field in ("pii_entities", "forbidden_keywords"):
                if not isinstance(reasons[field], list) or any(not isinstance(item, str) for item in reasons[field]):
                    raise ValueError(f"invalid {field}")
        records.append(record)
    digest = sha256(data).hexdigest()
    if manifest["status"] == "complete":
        if len(records) != len(cases):
            raise ValueError("complete manifest has missing records")
        errors = sum("error" in record for record in records)
        if type(manifest.get("record_count")) is not int or manifest["record_count"] != len(records):
            raise ValueError("completion record count mismatch")
        if type(manifest.get("error_count")) is not int or manifest["error_count"] != errors:
            raise ValueError("completion error count mismatch")
        if manifest.get("report_sha256") != digest:
            raise ValueError("report hash mismatch")
        if not isinstance(manifest.get("completed_at"), str) or not manifest["completed_at"].strip():
            raise ValueError("missing completion timestamp")
    elif any(field in manifest for field in ("record_count", "error_count", "report_sha256", "completed_at")):
        raise ValueError("running manifest contains completion evidence")
    return manifest, records, digest


def run(args, cases, selection) -> int:
    path = manifest_path(args.output)
    if not args.resume and (args.output.exists() or path.exists()):
        raise ValueError("refusing to overwrite report or manifest; use a new path or --resume")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("r+b" if args.resume else "x+b") as report:
        # Prevent two resumptions from sending or appending the same cases.
        fcntl.flock(report.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        config = {"tool": args.tool, "url": args.url, "timeout": args.timeout,
                  "pause": args.pause, "selection": selection}
        if args.resume:
            manifest, records, _ = read_run(args.output)
            if any(manifest.get(key) != value for key, value in config.items()):
                raise ValueError("resume configuration differs from manifest")
            if manifest["status"] == "complete":
                raise ValueError("run is already complete; refusing to change it")
        else:
            manifest = {
                **config, "format_version": 2, "producer": "common-http",
                "run_id": str(uuid4()), "corpus_version": CORPUS_VERSION,
                "corpus_sha256": corpus_sha256(cases),
                "expected_ids": [case.case_id for case in cases],
                "started_at": datetime.now(timezone.utc).isoformat(), "status": "running",
            }
            report.flush()
            os.fsync(report.fileno())
            write_manifest(path, manifest, initial=True)
            records = []
        report.seek(0, os.SEEK_END)
        for case in cases[len(records):]:
            started = time.perf_counter()
            record = {key: manifest[key] for key in (
                "run_id", "tool", "producer", "corpus_version", "corpus_sha256"
            )}
            record.update(timestamp=datetime.now(timezone.utc).isoformat(), case=case.to_dict())
            try:
                target = validate_target(call_target(args.url, case.message, args.timeout))
                record.update(
                    response=target["response"], blocked=target["blocked"],
                    blocked_at_layer=target["blocked_at_layer"],
                    filter_reasons=filter_reasons(target),
                    verdict=evaluate(case, target["response"], target["blocked"]).to_dict(),
                )
            except (OSError, HTTPException, ValueError) as error:
                record["error"] = f"{type(error).__name__}: {error}"
            record["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
            report.write((json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n").encode())
            report.flush()
            os.fsync(report.fileno())
            records.append(record)
            time.sleep(args.pause)
        # Re-read durable bytes before declaring completion, not just in-memory counts.
        _, records, digest = read_run(args.output)
        errors = sum("error" in record for record in records)
        manifest.update(status="complete", completed_at=datetime.now(timezone.utc).isoformat(),
                        record_count=len(records), error_count=errors, report_sha256=digest)
        write_manifest(path, manifest)
    print(f"report={args.output} complete=True records={len(records)} errors={errors}")
    return 1 if errors else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True, help="Run label only, not a native scanner adapter")
    parser.add_argument("--url", default="http://localhost:8000/chat")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0, help="0 runs the complete corpus")
    parser.add_argument("--vector", choices=ATTACK_VECTORS, help="Restrict to one attack vector")
    parser.add_argument("--pause", type=float, default=1.0, help="Seconds to pause after every request, including errors")
    parser.add_argument("--resume", action="store_true", help="Append only to a validated incomplete prefix with identical options")
    parser.add_argument(
        "--per-vector",
        type=int,
        default=0,
        help="Run this many cases from each vector; cannot be combined with --limit",
    )
    parser.add_argument(
        "--benign-controls",
        type=int,
        default=0,
        help="Fixed Spanish legitimate requests used to measure false positives",
    )
    parser.add_argument(
        "--controls-only",
        action="store_true",
        help="Run only --benign-controls legitimate requests",
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args(argv)
    selection = {key: getattr(args, key) for key in (
        "limit", "per_vector", "vector", "benign_controls", "controls_only"
    )}
    try:
        if not args.tool.strip():
            raise ValueError("--tool must be nonempty")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("--timeout must be finite and positive")
        if not math.isfinite(args.pause) or args.pause < 0:
            raise ValueError("--pause must be finite and nonnegative")
        cases = select_cases(**selection)
        return run(args, cases, selection)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted: run remains incomplete; --resume requires an intact prefix", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
