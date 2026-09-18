# Evidence Policy

## Core Rule

No model, scanner, tool, or benchmark output is a security verdict by itself. Record what was run and state what the result does not prove.

## Required Record

For a public security claim, record:

- Requirement or question being evaluated.
- Repository revision and relevant dependency or model hash.
- Command, configuration, tool version, and model identifier.
- Fixture sensitivity and redaction status.
- Timestamp, exit status, result, and artifact hash or location.
- Reviewer when human review is required.

## Safe Artifacts

Commit deterministic fixtures, schemas, expected results, sanitized summaries, and hashes. Do not commit credentials, private targets, raw prompts containing source material, model caches, local paths, full scanner reports, or generated runtime state.

## Result Language

Use bounded wording such as "observed for this fixture and configuration." Do not use "secure," "proven safe," "production-ready," or "industry default" without independently reviewable evidence matching that claim.
