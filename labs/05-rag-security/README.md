# Phase 4: RAG Security

## Scope

This lab evaluates a local RAG prototype with synthetic benign and adversarial documents. It examines retrieval poisoning, indirect prompt injection, and the effect of filtering retrieved chunks before they reach the model.

## Observations

In the tested corpus, maliciously phrased content could rank highly for a related query. Individual defenses, including a prompt-injection classifier, did not cover every synthetic pattern. Combining classifier and pattern-based checks blocked the tested adversarial documents while allowing the tested benign control.

These are bounded observations, not proof that the defenses protect other documents, models, languages, retrieval settings, or production workloads. The unverified historical Phase 3b `362/512 = 29.3%` claim is not used as evidence; see [Phase 3b.1](../04b-red-team-tool-comparison/README.md) for the current methodology.

## Safety

Use only synthetic documents and a local database. Do not index confidential material or expose the prototype as a production service. Treat retrieved text and model output as untrusted data. Human review remains required for sensitive actions.

## Reproducibility

Record the corpus revision, embedding and model versions, retrieval parameters, random settings, commands, raw responses, and errors. Repeat each bounded scenario and report exceptions. A passing test demonstrates only the stated fixture and configuration.
