# Harness Threat Model

## Assets

- Source trees submitted for local analysis.
- User messages evaluated by input controls.
- Normalized findings, calibration evidence, and redacted run records.
- Local scanner and model executables.

## Trust Boundaries

- A caller supplies paths, messages, and campaign manifests.
- Capabilities invoke external tools and receive untrusted output.
- The evidence store writes outside the analyzed workspace.
- Human review is the boundary between advisory evidence and a consequential decision.

## Primary Controls

- Canonical absolute-path validation and excluded-directory checks.
- Fixed subprocess argument lists and bounded timeouts.
- Strict normalization of tool output; malformed output is an explicit failure state.
- Redacted evidence storage with restrictive file permissions and retention limits.
- Explicit incomplete and failed states; absence of findings is never conflated with tool failure.
- No automatic authorization, deployment, or production gating.

## Out of Scope

The harness does not defend a production network, manage credentials, provide multi-tenancy isolation, or operate unreviewed agent tools. Those concerns require a separately approved design and are not implied by this repository.
