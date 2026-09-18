# CI Notes for LLM Red Teaming

## Why three tiers

A full Garak campaign over 512 prompts can take tens of minutes against a local model. Running that per commit would block every pull request. Split evaluation work into three tiers.

## Tiers

1. **Pull request gate (fast, deterministic):** schema validation, unit tests, and a fixed handful of high-signal cases from the versioned corpus. Minutes, not tens of minutes.
2. **Staging campaign (bounded):** a reduced Garak or runner-corpus campaign with a fixed case count, fixed corpus hash, and recorded tool and model versions.
3. **Scheduled campaign (full):** complete probe catalogs and red-team suites, run on a schedule with hardware that can sustain the load, and with thermal safeguards if needed.

## Rules that still apply in every tier

- Treat scanner verdicts as evidence, not facts; inspect raw outputs before reporting.
- Never count an inconclusive response as a defense success.
- Pin scanner versions and record corpus hashes before comparing runs.
- Cancelled or corrupt runs are discarded, never cited with partial percentages.

This lab compares scanner utility only on documented synthetic fixtures; see lab `04b-red-team-tool-comparison` for the current methodology.
