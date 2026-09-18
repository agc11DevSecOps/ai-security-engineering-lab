# Lab 03: Evidence-Grounded Threat Modeling

## Purpose

Demonstrate an evidence-grounded approach to generating and reviewing STRIDE threat-model drafts with a local language model.

## What this lab demonstrates

- Grounding threat statements in a bounded architecture description and evidence record.
- Constraining generated threats to the six STRIDE categories with structured output.
- Deduplicating similar threat descriptions with deterministic text comparison.
- Retrieving relevant evidence deterministically before asking a model for an advisory comparison.
- Identifying cases that require human review instead of treating model output as a fact-checking verdict.

## Scope and safety

This lab uses a sanitized, real-world-inspired reference application. The application accepts public support requests, validates a challenge response, applies request throttling, stores a limited request record, and sends an operational notification. The case intentionally includes two review topics: configuration that may not be consistently applied and data handling that differs across processing steps.

The case is generic. It contains no real domain names, service providers, target topology, personal references, credentials, or archived model outputs. Threats and model responses are untrusted drafts, not verified findings or authorization inputs.

## How to navigate/run

1. Provide a sanitized architecture description at `diagrams/architecture.mmd` and a bounded evidence record at `diagrams/evidence_record.md` before running generation scripts.
2. Run `python tests/generate_stride_v2.py` with an available local compatible inference endpoint to request evidence-cited threat drafts.
3. Run `python tests/dedup_threats.py <threats.json>` to produce a deterministic deduplicated copy.
4. Run a fact-checking variant with the threat file as its second argument, then route unsupported or inconsistent results to a reviewer.

## Evidence and results

Record the sanitized inputs, model identifier, prompt version, generated artifact hash, retrieval snippets, validation output, and reviewer disposition. The scripts report counts, STRIDE categories, retrieved evidence, and review states. Do not retain raw prompts or model outputs that contain sensitive source material.

## Limits

Lexical retrieval can omit relevant evidence or select contextually unrelated text. Structured output validates format, not factual accuracy. Language models can reverse negations, invent unsupported risks, or give contradictory explanations. A human reviewer must validate every consequential threat and mitigation against the approved evidence record.

## Connection to the harness

This lab supplies a draft-and-review pattern for the harness: deterministic evidence retrieval precedes model assistance, generated content remains untrusted, and only an authorized reviewer or deterministic policy may produce a security decision.
