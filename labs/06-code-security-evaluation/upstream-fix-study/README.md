# Phase 4e: Local Upstream Diagnosis

## Scope

This study diagnoses a local reproduction of a multi-file analysis failure in Vulnhuntr. It is a local investigation and proposed patch, not an upstream fix. No upstream project has been changed, accepted the diagnosis, or released a remedy as part of this lab.

## Local Diagnosis

The reproduced failure occurred when a relative scan root reached Jedi/Parso with unresolved path segments. In the local experiment, resolving the root before constructing the symbol extractor allowed the test lookup to proceed. A minimal proposed change is to normalize the CLI root path at the start of analysis.

## Evidence Boundary

This observation is limited to the tested dependency version, relative path, fixture, and local environment. It does not establish root cause for every upstream failure or prove that path normalization is sufficient. Model classification errors remained possible after context was available.

## Safe Reproduction

Use only the included disposable fixture and an isolated dependency environment. Do not patch a shared installation or production scanner. Preserve the exact dependency revision, patch diff, commands, logs, fixture revision, and before/after raw reports. Submit an upstream issue or pull request only after independently reproducing the behavior against a pinned upstream revision.
