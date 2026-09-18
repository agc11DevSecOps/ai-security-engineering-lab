# Runtime Rule: Absolute Paths Only at External Boundaries

## Guarantee

At every boundary with an external tool (subprocess, model, parser), paths are resolved to canonical absolute form and validated against the canonical workspace before use. A relative path is never passed to a tool whose working directory may differ from the intended one.

## Origin

The local Vulnhuntr diagnosis (Lab 06, upstream-fix study) showed that relative roots silently broke the symbol-extraction cache, so multi-file chains never resolved. A single path-normalization line fixed the infrastructure failure and proved it was independent of model quality.

## Where It Applies

- `BanditCapability` builds its command with `cwd=workspace_root` and an absolute target.
- `VulnhuntrCapability` enumerates and passes each file as an absolute path and re-normalizes tool output against the canonical target.
- The capability contract validates `target` and `workspace_root` as absolute and rejects relative, outside-workspace, or excluded paths.

## Regression Prevented

No capability can report a clean result after accidentally running a tool against a different tree than the one the user requested.
