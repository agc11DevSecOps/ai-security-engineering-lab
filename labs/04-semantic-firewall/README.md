# Phase 3: Semantic Firewall

## Scope

This local FastAPI prototype applies four controls to a chat request: prompt-injection screening, input PII anonymization, local LLM generation, and output filtering for PII, literal system-prompt fragments, and configured terms. It is a learning prototype, not a production security boundary.

## Safety

Run the service only on a trusted local environment. Do not send real credentials, personal data, or confidential prompts to the target. Logs may contain request metadata and must be protected or removed after testing.

## Observations

Small, local tests showed that the assembled layers can block direct injection attempts and anonymize selected PII. These are bounded observations for the tested prompts, model, configuration, and hardware. They do not prove protection against encoded, indirect, multilingual, multi-turn, or future attacks.

An earlier Phase 3b statement that indirect injection succeeded in `362/512 = 29.3%` of cases is not verified. The source Garak JSONL is unavailable, and the stated arithmetic is inconsistent. Do not cite that result as evidence. Use [Phase 3b.1](../04b-red-team-tool-comparison/README.md) for the current reproducible methodology.

## Reproducibility

Install the pinned dependencies, start the local model service, and run the unit tests before any HTTP test. Record the model version, configuration, corpus hash, timestamps, raw output, errors, and environment details. Treat incomplete runs, timeouts, and ambiguous responses as inconclusive rather than safe.

## Known Limits

- Prompt Guard is a classifier, not a guarantee.
- Literal prompt-leak matching can miss paraphrases.
- PII recognition can produce false positives and false negatives.
- This endpoint is stateless and does not evaluate retrieval-based indirect injection.
