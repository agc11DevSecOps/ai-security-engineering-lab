# Bounded Evidence Record — Lab 03 Reference Application

This record is the only admissible evidence for Lab 03 threat-model generation. It describes a sanitized, real-world-inspired public contact service. Every threat claim must cite a statement from this file.

## Confirmed facts

1. `api/routes.py:14` — the public submission endpoint accepts unauthenticated requests by design; the application publishes no private resources, so the absence of authentication is a design decision, not a vulnerability.
2. `api/rate_limit.py:9` — a global in-memory rate limiter exists with hardcoded request budgets; declared environment variables for the same limits are never read, so operator-provided configuration silently has no effect (dead configuration).
3. `api/store.py:32` — the free-text body of each request is encrypted at rest with an authenticated cipher.
4. `api/store.py:44` — the sender name and contact address fields are stored without encryption.
5. `api/notify.py:18` — the full request body is forwarded as plaintext to an external mail gateway, so a value protected at rest becomes unprotected in transit.
6. `api/verify.py:7` — the challenge-response token is verified server-side with the verification provider's API before acceptance.
7. `deploy/pipeline.yml:12` — deployment tokens are stored as CI secrets and referenced by name; token values do not appear in configuration files.

## Out-of-bounds statements

- Do not treat the missing authentication (fact 1) as a vulnerability.
- Do not claim deployment secrets are committed to the repository (fact 7 rules this out).
