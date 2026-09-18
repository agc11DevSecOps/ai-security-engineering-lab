# Harness Design

## Request-to-Evidence Flow

1. The CLI accepts exactly one task type and validates absolute paths or bounded standard input.
2. The router selects the capabilities allowed for that task.
3. Each capability converts untrusted tool output into a typed result or an explicit incomplete state.
4. The consolidator groups compatible findings without deleting conflicting evidence.
5. The trust-score module attaches advisory calibration evidence when the source and category are supported.
6. The evidence store writes redacted metadata outside the analyzed workspace.

## Separation of Roles

A capability can produce a normalized finding, but it cannot decide whether that finding is true, assign itself a final trust score, or trigger a high-impact action. The consolidator records agreement and disagreement; a human reviewer remains responsible for every consequential decision.

## Extension Rules

Add a capability only when its request boundary, output schema, failure states, and deterministic test seam are defined first. Use fixed subprocess argument lists, validate every returned path against the target, and preserve tool failure as an explicit status instead of treating it as a clean result.

## Evaluation Script

`scripts/measure_harness_value.py` replays the harness against the synthetic local-flow benchmark (`labs/06-code-security-evaluation/local-flow-benchmark`) and compares profile output to the versioned oracle. Its report is written under `calibrations/evidence/` and is data for review, not a gate.
