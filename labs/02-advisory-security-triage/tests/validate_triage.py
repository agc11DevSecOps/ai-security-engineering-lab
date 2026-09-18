"""Validate model-generated triage identifiers against original Bandit findings.

The check detects missing, duplicated, and invented identifiers without relying
on manual reading. It does not validate the model's security reasoning.
"""
import json
import re
from collections import Counter

with open("sample_findings/bandit_raw.json") as f:
    original = json.load(f)

original_ids = [r["test_id"] for r in original["results"]]
original_count = Counter(original_ids)

with open("sample_findings/triage_output.txt") as f:
    triage_text = f.read()

# Match identifiers such as [B608] and [B105].
found_ids = re.findall(r"\[(B\d{3})\]", triage_text)
found_count = Counter(found_ids)

print("=== Identifier Validation ===")
print(f"Original identifiers (Bandit): {dict(original_count)}")
print(f"Identifiers mentioned by the model: {dict(found_count)}")

errors = []
for tid, count in original_count.items():
    if found_count.get(tid, 0) != count:
        errors.append(f"  - {tid}: expected {count} occurrence(s), found {found_count.get(tid, 0)}")

extra = set(found_count) - set(original_count)
if extra:
    errors.append(f"  - Unexpected identifiers not present in the source: {extra}")

if errors:
    print("\nVALIDATION FAILURES:")
    for e in errors:
        print(e)
else:
    print("\nPASS: all identifiers match the source one-to-one.")
