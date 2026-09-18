# Harness Checkpoints

## C0 - Third-Party Tool And Skill Admission

- Named tool or skill, publisher, immutable source revision, and content hash are recorded.
- Current review status is recorded as evidence, not assumed approval.
- Every referenced file and executable is reviewed in an isolated environment before adoption.
- No secrets, tokens, or unapproved network side effects are used during evaluation.

## C1 - Threat And Boundary Model

- Assets, actors, trust boundaries, attacker goals, and assumptions are explicit and versioned.
- Prompts, code, tool output, and imported findings are modeled as untrusted input.
- Abuse cases map to capability-level requirements and tests.

## C2 - Capability Specification

- Requirements are verifiable and have stable identifiers.
- The design record covers the public test seam, trust boundaries, failure states, and alternatives considered.
- Tasks are discrete and ordered; each requirement links to implementation and verification work.

## C3 - Implementation

- A capability returns normalized findings and never computes its own final trust score.
- Paths are absolute at every external-tool boundary.
- Model output is schema-validated before use.
- Agreement, conflict, and missing evidence remain observable to the caller.

## C4 - Verification And Release

- Unit and integration tests cover expected, malformed, and adversarial input.
- Deterministic controls and capability tests pass from a clean invocation.
- A known ground-truth target is exercised when one exists.
- The verification record satisfies `AGENTS.md`, and a reviewer confirms any security conclusion or exception.
