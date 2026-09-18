# Phase 4c: Dynamic Validation Study

## Scope

This lab evaluates an autonomous security-testing agent against isolated, intentionally vulnerable targets. It compares dynamic proof-of-concept validation with static LLM-assisted analysis.

## Observations

In one bounded local run, the agent followed a three-file SQL-injection path and validated the issue through HTTP requests. A separate broader target run was incomplete because of resource limits; only artifacts preserved and independently checked from that run may be cited. These results do not establish general agent accuracy, safety, or suitability for CI.

## Safety

Run only in a disposable sandbox with intentionally vulnerable targets. Do not scan public, customer, or production systems. Set time, token, network, and spending limits before execution. Review all agent actions and outputs before using them.

## Reproducibility

Record the target image or revision, agent and model version, authorization boundary, commands, budgets, raw reports, request logs, and exit status. Treat interrupted, rate-limited, or overwritten reports as incomplete. Results are bounded observations of a specific target and run.
