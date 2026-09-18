# AI Security Engineering Lab

An evidence-driven, local-first lab for learning how to build and evaluate security controls for model artifacts, LLM applications, RAG systems, and AI-assisted application-security workflows.

This repository is a technical portfolio and a reproducible learning resource. It deliberately records what did not work, where evidence is incomplete, and where a human reviewer remains required.

## Start Here

1. Read [docs/PROJECT_CHARTER.md](docs/PROJECT_CHARTER.md) for the public scope and safety rules.
2. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the relationship between the labs and the harness.
3. Start with `labs/00-local-security-foundation/` and follow the labs in order.
4. Read [harness/README.md](harness/README.md) for the flagship implementation.

## What This Project Is

- A local-first AI security engineering lab.
- A set of small, scoped experiments with stated assumptions and limits.
- A reference implementation of a bounded, advisory security harness.
- A demonstration of defense in depth: deterministic controls retain authority; model output remains untrusted evidence.

## What This Project Is Not

- A production-ready CI/CD platform or security gate.
- A certification that a firewall, RAG system, model, or scanner is secure.
- An autonomous security decision maker.
- A general benchmark or a substitute for a threat model, a security review, or production monitoring.

## Learning Path

| Area | Directory | What to learn |
| --- | --- | --- |
| Foundation | `labs/00-local-security-foundation/` | Local PII and prompt-injection controls have measurable blind spots. |
| Model artifacts | `labs/01-secure-model-artifacts/` | Scan, safe serialization, signing, and policy are distinct controls. |
| Advisory triage | `labs/02-advisory-security-triage/` | Schemas constrain structure, not model reasoning. |
| Threat modeling | `labs/03-evidence-grounded-threat-modeling/` | Grounding improves drafts; people still validate security conclusions. |
| LLM boundaries | `labs/04-semantic-firewall/` | Layering controls is useful but does not create a complete boundary. |
| Red teaming | `labs/04a-red-teaming-with-garak/` | Scanner results require evidence, language awareness, and methodology. |
| RAG security | `labs/05-rag-security/` | Retrieval poisoning needs multiple complementary controls. |
| Code security | `labs/06-code-security-evaluation/` | Deterministic analyzers, AI assistance, and dynamic validation have different roles. |
| Flagship | `harness/` | A bounded harness preserves disagreement and requires human approval. |

## Quick Verification

The repository CI only runs deterministic, offline checks. It does not download models, call hosted APIs, or run expensive red-team campaigns.

```bash
make check
make test
```

Every tool used in the project — what it does, why it was chosen, and where its limits were observed — is documented in [docs/TOOL_CATALOG.md](docs/TOOL_CATALOG.md).

See [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) before running a model-backed experiment.

## Evidence Standard

Each public claim must state its scope, command, tool and model versions, inputs, result, limitations, and review status. Read [docs/EVIDENCE_POLICY.md](docs/EVIDENCE_POLICY.md) before adding a result.

## Project Status

Version 1 is limited to the labs and bounded harness included here. The work intentionally avoids claiming a production CI/CD implementation or a fully autonomous security workflow.

## Version 2 Direction

Version 2 is in progress and explores MCP security, agentic AI security, and ways to reduce unnecessary harness complexity. These areas are intentionally outside the scope of this Version 1 release.
