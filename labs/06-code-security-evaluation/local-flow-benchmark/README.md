# Phase 4f: Local Multi-File Flow Benchmark

## Scope

This benchmark measures Bandit, a local Semgrep OSS rule, and CodeQL on synthetic Python fixtures. It distinguishes detecting a relevant CWE from showing a path across route, service, and repository files.

## Run

```bash
python3 scripts/run_local_eval.py
python3 scripts/score.py
python3 scripts/triage_results.py
pytest -q tests
```

The runner retains raw output and tool states. The scorer uses `ground_truth.json`; the optional LLM triage may explain or prioritize deterministic findings but does not change detection metrics.

## Interpretation

Any generated scorecard is a bounded observation for the pinned tools, local rules, 25 synthetic cases, and tested framework patterns. A tool failure is not a clean result. CodeQL flow evidence is credited only when its SARIF includes the expected files. Do not generalize these metrics to other languages, frameworks, query suites, or CI workloads.

## Safety And Reproducibility

Fixtures intentionally contain unsafe patterns and must not be deployed or connected to untrusted traffic. Run them only in the local lab. Record tool versions, configuration, fixture revision, commands, raw artifacts, and errors. Human security review is required before deriving any policy from the results.
