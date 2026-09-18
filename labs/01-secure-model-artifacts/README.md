# Lab 01: Secure Model Artifacts

## Purpose

Demonstrate a defense-in-depth workflow for admitting serialized model artifacts while minimizing deserialization risk.

## What this lab demonstrates

- Creating synthetic benign and intentionally unsafe pickle fixtures for static analysis.
- Using a scanner to inspect code-capable serialization formats without loading them.
- Converting a verified control artifact to `safetensors`, a data-only format.
- Separating static scanning, format safety, signature verification, and policy admission as distinct controls.

## Scope and safety

The unsafe pickle fixture contains only a local, non-destructive demonstration payload. Never load it with `pickle.load()` or an equivalent deserializer. The conversion script loads only the synthetic control fixture after it has been reviewed and scanned.

This lab is an educational artifact workflow. It does not establish provenance, safety, or fitness of a real model, and it does not deploy an admission controller.

## How to navigate/run

1. Review `malicious_samples/create_malicious_pickle.py` and `safe_samples/create_safe_pickle.py` before generating fixtures.
2. Generate the control and unsafe fixtures from the lab directory with their respective Python scripts.
3. Scan serialized artifacts with the scanner already installed in your local environment; do not load the unsafe fixture.
4. Run `python safe_samples/convert_to_safetensors.py` only for the reviewed control artifact.
5. Review the policy fixtures in `opa_policy/` when evaluating policy logic with an already installed policy engine.

## Evidence and results

Expected evidence includes a scanner finding for the unsafe fixture, no scanner finding for the control fixture, successful `safetensors` round-trip output, and signature or policy evaluation records where those local tools are available. Record tool version, artifact hash, command, timestamp, and result for any security decision.

## Limits

Static scanning can miss unknown techniques. A data-only format reduces deserialization risk but does not prove model behavior, provenance, licensing, or absence of poisoned weights. A signature proves integrity relative to a trusted key; it does not make an untrusted signer trustworthy.

## Connection to the harness

The artifact checks are admission evidence for the harness. A downstream system should independently verify hashes, signatures, approved provenance, and policy before making a deployment or execution decision.
