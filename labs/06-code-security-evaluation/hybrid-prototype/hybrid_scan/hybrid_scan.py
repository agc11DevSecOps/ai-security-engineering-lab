#!/usr/bin/env python3
"""CLI for the experimental deterministic SAST and LLM scanner pipeline.

It runs Bandit and Vulnhuntr and assigns review-priority bands to correlated
findings. The bands are not vulnerability verdicts.
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from scanners.bandit_runner import run_bandit
from scanners.vulnhuntr_runner import run_vulnhuntr, DEFAULT_MODEL
from core.consolidator import consolidate


def main():
    parser = argparse.ArgumentParser(description="Experimental SAST and LLM scanner pipeline")
    parser.add_argument("--target", required=True, help="Repository or directory to scan")
    parser.add_argument("--output", default="reports", help="Directory for the JSON report")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model for Vulnhuntr")
    parser.add_argument("--skip-vulnhuntr", action="store_true", help="Run Bandit only")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: target does not exist: '{target_path}'", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    project_name = target_path.name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"hybrid_scan_{project_name}_{timestamp}.json"

    print(f"=== hybrid_scan: {target_path} ===\n")

    print("[1/3] Running Bandit...")
    bandit_findings = run_bandit(str(target_path))
    print(f"  {len(bandit_findings)} findings\n")

    vulnhuntr_findings = []
    if not args.skip_vulnhuntr:
        print("[2/3] Running Vulnhuntr (may take several minutes)...")
        vulnhuntr_findings = run_vulnhuntr(str(target_path), model=args.model)
        print(f"  {len(vulnhuntr_findings)} findings\n")
    else:
        print("[2/3] Vulnhuntr skipped (--skip-vulnhuntr)\n")

    print("[3/3] Consolidating...")
    result = consolidate(bandit_findings, vulnhuntr_findings)

    by_level = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in result:
        by_level[r["confidence_level"]] += 1

    report = {
        "project": project_name,
        "target_path": str(target_path),
        "scanned_at": datetime.now().isoformat(),
        "model_used": args.model if not args.skip_vulnhuntr else None,
        "summary": {
            "total_findings": len(result),
            "by_confidence": by_level,
            "bandit_raw_count": len(bandit_findings),
            "vulnhuntr_raw_count": len(vulnhuntr_findings),
        },
        "findings": result,
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\n=== SUMMARY ===")
    print(f"Total consolidated findings: {len(result)}")
    print(f"  HIGH review priority:   {by_level['HIGH']}")
    print(f"  MEDIUM review priority: {by_level['MEDIUM']}")
    print(f"  LOW review priority:    {by_level['LOW']}")
    print(f"\nReport written to: {output_file}")


if __name__ == "__main__":
    main()
