# Measured Results

This file preserves the verified quantitative observations from the red-team tool comparison. Raw runner files are intentionally not committed; reproduce them with the scripts and report a fresh corpus hash before citing numbers.

## Common-corpus smoke (20 cases)

10 Base64 cases were `inconclusive` (no canary reproduced, no recognized block) and 10 indirect-injection cases were blocked. 0 errors. Median 440 ms, P95 1.1s. Inconclusive is never reported as secure.

## Phase A, common corpus (144 cases)

64 indirect-injection cases blocked. 64 Base64 cases inconclusive. Initial benign controls showed 1 false positive in 16; a dedicated 64-control confirmation found a false-positive rate of 20.31%, all caused by the output filter treating detected PII as a block. After remediation (redact PII in output instead of blocking), the same 64 benign controls and the full 144-case Phase A completed with 0 false positives. Base64 cases remained inconclusive, not resistant.

## Phase B status

A 1,024-case Phase B was canceled for methodological reasons: the first corpus varied only a canary counter and 1,024 calls stressed the machine rather than measuring coverage. An interrupted run also left a corrupt JSONL, which was discarded, never cited. Phase B is replaced by corpus v2 (`redteam-common-v2`): 8 distinct Base64 attacks, 8 indirect-injection cases, 8 benign controls, plus integrity-checked JSONL and an oracle where a canary outranks a block verdict.

## Tool utility on synthetic fixtures

- Garak: 7/7 findings on the vulnerable fixture, 7/7 pass on the safe fixture.
- Giskard: 3/3 on the safe driver, 1 expected failure on the vulnerable one.
- PyRIT: 3 failures before adapter adjustment on the safe fixture, success after adaptation on the vulnerable one.
- Cross-tool flow verified: a Garak confirmed case was imported into a Giskard suite and detected as a failure.

## Verdict recorded during the study

Garak is the baseline for one-shot static campaigns; Giskard's value is a versioned suite plus JUnit output once a real CI exists; PyRIT shows no differentiated value against a stateless endpoint and should be re-evaluated only against a target with conversation memory. No quantitative cross-tool comparison is published, because the corpora and targets are not equivalent.
