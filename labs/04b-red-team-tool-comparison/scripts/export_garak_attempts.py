#!/usr/bin/env python3
"""Extract immutable attempt prompts from a Garak JSONL report."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=0)
    args = parser.parse_args()

    attempts = []
    with args.report.open(encoding="utf-8") as source:
        for line in source:
            item = json.loads(line)
            if item.get("entry_type") != "attempt":
                continue
            attempts.append(
                {
                    "attempt_uuid": item.get("uuid"),
                    "prompt": item.get("prompt"),
                    "outputs": item.get("outputs"),
                    "detector_results": item.get("detector_results"),
                }
            )
    if args.expected_count and len(attempts) != args.expected_count:
        raise SystemExit(
            f"expected {args.expected_count} attempts, found {len(attempts)}; output not written"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as target:
        for attempt in attempts:
            target.write(json.dumps(attempt, ensure_ascii=True) + "\n")
    print(f"exported {len(attempts)} attempts to {args.output}")


if __name__ == "__main__":
    main()
