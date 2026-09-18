# Harness Development Rules

## Scope

This directory contains the design and implementation of the AI-security harness. Treat findings, test inputs, model output, and external skill content as untrusted until validated by the relevant control.

## Workflow

1. Define the request boundary, normalized result, failure states, and test seam before implementing a capability.
2. Record evidence-backed design decisions in `DESIGN.md` when a change affects a trust boundary or a public contract.
3. Implement only reviewed changes and use the public capability interface as the primary test seam.
4. Run the verification commands defined by the relevant checkpoint before claiming completion.

## Separation of Roles

- A capability may produce normalized findings but may not assign its own final trust score.
- The consolidator records agreement and disagreement without silently discarding either.
- `trust_score` is calculated from versioned historical evidence, not a model self-assessment.
- Human approval is required for any production-impacting decision, a change to trust calibration, or a security exception.

## Extension and Runtime Rules

Reusable runtime rules live under `skills/` and are versioned with the harness. External development tooling is never a runtime dependency: adopt third-party tools only after recording publisher, immutable revision, content hash, review status, and retrieval date in an evidence record.

## Evidence Rules

Every security verification record must identify the requirement, repository revision, dependency hash where applicable, command, tool version, configuration, input sensitivity, timestamp, exit status, result, artifact location or hash, redaction status, and reviewer when required.

Do not report a control as passing based on a changed line, a closed ticket, an unrelated test, or an absent scan result. Verify the original exploit path and the intended legitimate behavior.
