#!/usr/bin/env python3
"""Summarize normalized common-corpus JSONL reports without hiding errors."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from statistics import median

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.run_target_corpus import read_run


def percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * ratio))]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    try:
        manifest, records, _ = read_run(args.report)
    except (OSError, ValueError) as error:
        print(f"integrity_error: {error}; complete=False", file=sys.stderr)
        return 1

    outcomes: Counter[str] = Counter()
    vectors: Counter[str] = Counter()
    elapsed: list[float] = []
    errors = 0
    vector_outcomes = {}
    for record in records:
        elapsed.append(record["elapsed_ms"])
        vector = record["case"]["vector"]
        vectors[vector] += 1
        outcome = "error" if "error" in record else record["verdict"]["outcome"]
        vector_outcomes.setdefault(vector, Counter())[outcome] += 1
        if outcome == "error":
            errors += 1
        else:
            outcomes[outcome] += 1

    total = sum(outcomes.values()) + errors
    attack_outcomes = sum(
        count
        for outcome, count in outcomes.items()
        if outcome in {"attack_succeeded", "blocked", "inconclusive"}
    )
    controls = outcomes["allowed"] + outcomes["false_positive"]
    print(f"report={args.report}")
    complete = manifest["status"] == "complete"
    print(f"producer=common-http tool={manifest['tool']} corpus_version={manifest['corpus_version']}")
    print(f"complete={complete} expected={len(manifest['expected_ids'])} missing={len(manifest['expected_ids']) - total}")
    print(f"total={total} errors={errors} vectors={dict(vectors)}")
    print(f"outcomes={dict(outcomes)}")
    for vector, counts in vector_outcomes.items():
        print(f"vector={vector} outcomes={dict(counts)}")
    # Incomplete/error-bearing runs are diagnostics, never headline success rates.
    if complete and not errors and attack_outcomes:
        print(
            "attack_rates "
            f"succeeded={100 * outcomes['attack_succeeded'] / attack_outcomes:.2f}% "
            f"blocked={100 * outcomes['blocked'] / attack_outcomes:.2f}% "
            f"inconclusive={100 * outcomes['inconclusive'] / attack_outcomes:.2f}%"
        )
    if complete and not errors and controls:
        print(
            "control_rates "
            f"false_positive={100 * outcomes['false_positive'] / controls:.2f}% "
            f"allowed={100 * outcomes['allowed'] / controls:.2f}%"
        )
    if elapsed:
        print(f"latency_ms median={median(elapsed):.2f} p95={percentile(elapsed, 0.95):.2f}")
    else:
        print("latency_ms unavailable (no records)")
    if not complete or errors:
        print("rates_suppressed: incomplete run or request errors")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
