# Phase 4d: Hybrid Bandit and Vulnhuntr Prototype

## Scope

This experimental CLI runs Bandit and Vulnhuntr on a Python target, normalizes their results, and produces one JSON report. It prioritizes findings for human review; it does not validate exploitability, prove data flow, or provide a CI gate.

## Result Interpretation

`HIGH` means both tools reported an equivalent category in the same normalized file. `MEDIUM` is a Bandit-only result. `LOW` is a Vulnhuntr-only result. These are review priorities, not vulnerability verdicts. Local LLM results in this study included false positives, malformed output, and timeouts.

## Safety And Reproducibility

Scan only disposable lab targets. Scanner output, LLM output, and target files are untrusted. Isolate the scan workspace because tools may write artifacts. Record tool and model versions, command lines, configuration, target revision, raw reports, timeouts, and failures. Results are bounded observations of the listed target and environment.

## Next Work

Add explicit scanner states, timeout handling, isolated execution, blind fixtures, and automated tests before considering CI integration.
