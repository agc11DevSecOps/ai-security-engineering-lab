# Architecture Guide

## Two Layers

The repository has two layers.

| Layer | Location | Role |
| --- | --- | --- |
| Learning labs | `labs/` | Small experiments that isolate one control or failure mode. |
| Bounded harness | `harness/` | A reusable local CLI that applies selected capabilities and records redacted evidence. |

## How the Labs Lead to the Harness

Labs 00-05 establish individual controls and their limits. Lab 06 compares code-security signals. The harness converts the recurring lessons into active boundaries:

- Requests are validated before a capability runs.
- Targets must be absolute, inside an approved workspace, and outside excluded paths.
- Capabilities return normalized findings or control evidence, not deployment decisions.
- The consolidator preserves agreement and disagreement.
- Trust scoring uses versioned evidence rather than a model self-assessment.
- Evidence is redacted and stored outside the workspace.
- A human approval remains required for a production-impacting action.

## Reading the Harness

1. Start at `harness/harness.py` for the command-line flow.
2. Read `harness/core/capability.py` for request and result contracts.
3. Read `harness/core/router.py` for capability selection.
4. Read `harness/core/consolidator.py` and `harness/core/trust_score.py` for review prioritization.
5. Read `harness/tests/` alongside the modules; the tests describe intended boundaries.
