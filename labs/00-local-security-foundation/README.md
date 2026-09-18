# Lab 00: Local Security Foundation

## Purpose

Establish a local foundation for evaluating AI security controls without sending laboratory inputs to a hosted inference service. The lab introduces personally identifiable information (PII) detection and prompt-injection classification as separate controls.

## What this lab demonstrates

- Configuring a local multilingual PII detection and anonymization workflow.
- Applying a narrow false-positive allowlist instead of raising a global confidence threshold that could reduce detection coverage.
- Evaluating a prompt-injection classifier with benign, direct-injection, indirect-injection, multilingual, and obfuscated test cases.
- Documenting that a classifier is one layer of defense, not an authorization decision maker.

## Scope and safety

All examples use synthetic content. The scripts are local demonstrations and do not connect a classifier to production actions. Treat model output as untrusted: a classification result must be combined with input normalization, authorization boundaries, output handling, and human review where appropriate.

The optional model-backed scripts may require models and language resources that are already available in the local environment. This repository does not download them.

## How to navigate/run

1. Review `tests/nlp_config.yaml` to see the configured language models.
2. Run `python tests/test_presidio.py` from this directory to exercise PII detection and anonymization.
3. Run `python tests/test_promptguard.py` or `python tests/test_promptguard_advanced.py` only when the referenced local model artifacts are available.
4. Use `python tests/test_promptguard_oficial.py` only when access to the configured gated model has been authorized and `HF_TOKEN` is set locally.

## Evidence and results

The PII script prints detected entity types and anonymized text. The classifier scripts print each test category, the expected classification, the model classification, and timing information. The advanced suite is intended to reveal both coverage and blind spots; it is not a benchmark or a security certification.

## Limits

Entity-recognition confidence scores are recognizer-specific and require validation against representative, approved data. Prompt-injection classifiers can miss encoded, split, or context-dependent instructions and can produce false positives. No result from this lab establishes that an AI application is safe for production use.

## Connection to the harness

This lab provides local control examples for later harness stages. Its outputs are evidence for engineering review only; they must not directly permit tool use, deployment, data release, or other high-impact actions.
