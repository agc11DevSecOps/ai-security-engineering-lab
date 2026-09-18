"""Deduplicate advisory STRIDE threats using deterministic text similarity.

This standard-library-only heuristic retains the highest-severity near-duplicate.
It is not semantic similarity and does not validate threat accuracy.
"""
import sys
import json
from difflib import SequenceMatcher

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SIMILARITY_THRESHOLD = 0.80


def similarity(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def dedup(threats):
    kept = []
    for t in threats:
        duplicate_of = None
        for i, k in enumerate(kept):
            sim = similarity(t.get("description", ""), k.get("description", ""))
            if sim >= SIMILARITY_THRESHOLD:
                duplicate_of = i
                break
        if duplicate_of is None:
            kept.append(t)
        else:
            existing = kept[duplicate_of]
            if SEVERITY_ORDER.get(t.get("severity"), 0) > SEVERITY_ORDER.get(existing.get("severity"), 0):
                kept[duplicate_of] = t

    return kept


def main():
    input_path = sys.argv[1]
    with open(input_path) as f:
        data = json.load(f)

    threats = data.get("threats", [])
    deduped = dedup(threats)

    print(f"Original: {len(threats)} threats")
    print(f"After deduplication (similarity threshold {SIMILARITY_THRESHOLD}): {len(deduped)} threats\n")

    for t in deduped:
        print(f"[{t.get('severity')}] {t.get('stride_category')} - {t.get('component')}")
        print(f"  {t.get('description')}")
        print("-" * 70)

    output_path = input_path.replace(".json", "_deduped.json")
    with open(output_path, "w") as f:
        json.dump({"threats": deduped}, f, indent=2, ensure_ascii=False)
    print(f"\nSaved to: {output_path}")


if __name__ == "__main__":
    main()
