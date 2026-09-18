# Lab 02: Advisory Security Triage

## Purpose

Explore how a local language model can summarize and prioritize static-analysis findings while keeping deterministic validation and human accountability in the workflow.

## What this lab demonstrates

- Generating synthetic static-analysis findings from intentionally vulnerable demonstration code.
- Asking a local model to produce structured triage with a constrained JSON schema.
- Checking that every source finding is represented exactly once and that no identifiers are invented.
- Formatting an already reviewed triage result for an optional webhook notification.

## Scope and safety

`vulnerable_code/app.py` is intentionally unsafe fixture code. Do not execute, deploy, import, or reuse it. Its placeholder values are explicitly synthetic and are not credentials. The model is advisory only: it must not autonomously block releases, send notifications, or override a security review.

The webhook script sends data only when a locally configured URL is provided. Do not place real findings, credentials, or sensitive reasoning in an unapproved notification channel.

## How to navigate/run

1. Review `vulnerable_code/app.py` as static-analysis input only.
2. Produce a Bandit JSON report in the expected `sample_findings/` location using tooling already available locally.
3. Run `tests/triage_v3.py` against an available local inference endpoint to create constrained JSON output.
4. Run `tests/validate_triage.py` to compare identifiers with the original findings.
5. Review the output before optionally invoking `tests/send_to_slack.py` with an approved test webhook.

## Evidence and results

The validation script reports missing, duplicated, and unexpected identifiers. The structured triage scripts report parsing status, item count, prioritization categories, and known semantic checks. Preserve the source report, model identifier, prompt version, validation output, and reviewer decision as evidence.

## Limits

Schema enforcement verifies structure, not security judgment. A model can misread a finding, assign an unsafe priority, or produce inconsistent reasoning even at deterministic settings. Keyword checks are narrow regression signals, not proof of semantic correctness. Human review remains required before merge gates or notifications.

## Connection to the harness

This lab produces advisory evidence that a harness can display to a reviewer. The harness must preserve the original scanner result, apply deterministic validation, and require an authorized human or policy decision for consequential actions.
