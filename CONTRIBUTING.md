# Contributing

## Before Opening a Change

1. Keep the change within Version 1 scope: Labs 00-06 and the bounded harness.
2. Use professional US English for documentation, code comments, and user-facing text.
3. Do not add secrets, private targets, local paths, raw model prompts, scanner logs, or generated reports.
4. Treat model and tool output as untrusted evidence, never as an authorization or security verdict.
5. Add or update deterministic tests for changed harness behavior.

## Documentation Style

Write for a reader who understands basic Python but is new to AI security. Explain why a security boundary exists, what it accepts, what it rejects, and what it cannot prove. Prefer a concise docstring or a comment explaining a non-obvious decision over line-by-line narration.

## Verification

Run the deterministic checks before proposing a change:

```bash
make check
make test
```

Model-backed, networked, or long-running campaigns require a separate approved evidence record. See [docs/EVIDENCE_POLICY.md](docs/EVIDENCE_POLICY.md).
