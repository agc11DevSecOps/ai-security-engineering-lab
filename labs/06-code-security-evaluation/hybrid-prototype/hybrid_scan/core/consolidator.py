"""Consolidate findings from multiple scanners into review-priority bands.

Findings match only when they share a normalized file and equivalent category.
The resulting bands prioritize review; they do not confirm exploitability or a
complete source-to-sink flow.
"""
from core.finding import Finding


# Map Bandit rule IDs to Vulnhuntr-style categories for comparison.
CATEGORY_EQUIVALENCE = {
    "B608": "SQLI",       # Bandit: SQL injection through concatenation
    "B602": "RCE",        # Bandit: subprocess with shell=True
    "B301": "RCE",        # Bandit: unsafe pickle use
    "B307": "RCE",        # Bandit: eval()
    "B324": "CRYPTO_WEAK",
    "B105": "HARDCODED_SECRET",
}


def _bandit_category(rule_id: str) -> str:
    return CATEGORY_EQUIVALENCE.get(rule_id, rule_id)


def consolidate(bandit_findings: list[Finding], vulnhuntr_findings: list[Finding]) -> list[dict]:
    consolidated = []
    used_vulnhuntr_idx = set()

    files_with_bandit = {f.file_path for f in bandit_findings}

    for bf in bandit_findings:
        bandit_category = _bandit_category(bf.rule_id)
        matched_vf = None

        for i, vf in enumerate(vulnhuntr_findings):
            if i in used_vulnhuntr_idx:
                continue
            if vf.file_path != bf.file_path:
                continue
            vulnhuntr_category = vf.rule_id.upper()
            if vulnhuntr_category == bandit_category or vulnhuntr_category in bandit_category:
                matched_vf = vf
                used_vulnhuntr_idx.add(i)
                break

        if matched_vf:
            consolidated.append({
                "file_path": bf.file_path,
                "line": bf.line,
                "confidence_level": "HIGH",
                "reason": "Bandit and Vulnhuntr reported an equivalent category in the same file",
                "confirmed_by": ["bandit", "vulnhuntr"],
                "bandit": bf.to_dict(),
                "vulnhuntr": matched_vf.to_dict(),
            })
        else:
            consolidated.append({
                "file_path": bf.file_path,
                "line": bf.line,
                "confidence_level": "MEDIUM",
                "reason": "Bandit syntactic finding without an equivalent Vulnhuntr result",
                "confirmed_by": ["bandit"],
                "bandit": bf.to_dict(),
            })

    for i, vf in enumerate(vulnhuntr_findings):
        if i in used_vulnhuntr_idx:
            continue
        # Vulnhuntr found an item in a file that Bandit did not flag.
        risk_note = ""
        if vf.file_path not in files_with_bandit:
            risk_note = " (no Bandit finding in this file; require careful human review)"
        consolidated.append({
            "file_path": vf.file_path,
            "line": vf.line,
            "confidence_level": "LOW",
            "reason": f"Vulnhuntr-only finding without Bandit support{risk_note}",
            "confirmed_by": ["vulnhuntr"],
            "vulnhuntr": vf.to_dict(),
        })

    return consolidated


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from scanners.bandit_runner import run_bandit
    from scanners.vulnhuntr_runner import run_vulnhuntr

    target = sys.argv[1] if len(sys.argv) > 1 else "../target"

    print("=== Running Bandit ===")
    bandit_findings = run_bandit(target)
    print(f"{len(bandit_findings)} findings\n")

    print("=== Running Vulnhuntr (may take several minutes) ===")
    vulnhuntr_findings = run_vulnhuntr(target)
    print(f"{len(vulnhuntr_findings)} findings\n")

    print("=== Consolidating ===")
    result = consolidate(bandit_findings, vulnhuntr_findings)

    by_level = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in result:
        by_level[r["confidence_level"]] += 1

    print(f"\nTotal consolidated findings: {len(result)}")
    print(f"  HIGH review priority: {by_level['HIGH']}")
    print(f"  MEDIUM review priority: {by_level['MEDIUM']}")
    print(f"  LOW review priority: {by_level['LOW']}\n")

    for r in result:
        print(f"[{r['confidence_level']}] {r['file_path']}:{r.get('line', '?')}")
        print(f"  {r['reason']}")
        print()
