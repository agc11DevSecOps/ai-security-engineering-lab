# Phase 3b: Garak Red-Team Study

## Scope

This historical study used Garak against the local Phase 3 firewall. It documents detector behavior and operational lessons; it is not a certification of the firewall or Garak.

## Evidence Boundary

The original Garak JSONL for the reported indirect-injection run is unavailable. Therefore the historical claim `362/512 = 29.3%` cannot be verified and must not be presented as a measured result. The arithmetic is also inconsistent: `362/512` is approximately `70.7%`, not `29.3%`.

The current reproducible approach is [Phase 3b.1](../04b-red-team-tool-comparison/README.md). It uses a versioned synthetic corpus, a conservative canary-based oracle, integrity-checked JSONL, and explicit treatment of errors and inconclusive responses.

## Historical Notes

The Base64 and refusal-detector observations remain historical notes only unless their original artifacts are recovered and independently reviewed. A detector that does not recognize a refusal in the response language can misclassify a blocked request; inspect raw outputs before treating a scanner verdict as a security result.

## Safety And Reproducibility

Run only against the local lab target with synthetic prompts and canaries. Do not use production endpoints, credentials, or private documents. Preserve the scanner version, configuration, target version, raw JSONL, command output, timestamps, and error records. A completed run is still a bounded observation for its exact target and corpus.
