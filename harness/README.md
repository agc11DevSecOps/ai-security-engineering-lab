# Bounded AI-Security Harness

The harness is the flagship artifact of this repository. It is a local command-line program that runs approved security capabilities, normalizes their evidence, preserves disagreement, and stores a redacted record outside the target workspace.

It does **not** make a deployment decision, block a merge, or approve a production action.

## Why It Exists

The labs repeatedly showed the same failure mode: a scanner can be incomplete, a model can be structurally valid but semantically wrong, and a successful run does not prove a system is safe. The harness turns those lessons into boundaries active on every run.

## Read This First

1. `harness.py` parses the local CLI request and builds the report.
2. `core/capability.py` validates requests before tools run.
3. `core/router.py` selects capabilities for an approved task type.
4. `core/consolidator.py` keeps both agreement and disagreement visible.
5. `core/evidence_store.py` persists redacted metadata outside the workspace.
6. `tests/` demonstrates each boundary with deterministic unit tests.

## Safety Boundaries

- Only absolute targets inside an explicit workspace are accepted.
- Sensitive paths such as `.git`, `.ssh`, `.venv`, and `node_modules` are rejected.
- The default analysis profile is `fast` and uses deterministic local analysis.
- The `deep` profile adds advisory LLM analysis; it is opt-in and non-blocking.
- Model and tool output is validated before normalization.
- A capability cannot assign its own final trust score.
- Trust scores are advisory research signals derived from versioned calibration evidence.
- Input-guard messages are read from standard input so they never enter command history.

## Example

Run this only against a disposable local workspace:

```bash
cd harness
python3 harness.py run \
  --task code_analysis \
  --workspace-root /absolute/path/to/workspace \
  --target /absolute/path/to/workspace/project
```

The command emits a JSON report. A non-zero exit code means at least one capability was incomplete, failed, or its redacted evidence record could not be stored. A zero exit code is **not** a statement that the target is safe.

## Verification

```bash
cd harness
python3 -m unittest discover -s tests -v
```

Read [DESIGN.md](DESIGN.md), [THREAT_MODEL.md](THREAT_MODEL.md), and [CHECKPOINTS.md](CHECKPOINTS.md) before extending a capability.

## Limits

The harness is a local research implementation. It does not provide authentication, network isolation, distributed execution, live MCP tooling, production key management, or automated incident response. Version 2 work is intentionally outside this release.
