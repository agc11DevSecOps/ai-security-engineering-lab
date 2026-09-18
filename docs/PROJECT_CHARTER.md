# Project Charter

## Purpose

AI Security Engineering Lab is a public, local-first learning project. It explains how a set of bounded experiments led to a reusable AI-security harness. The repository favors reproducible evidence over product claims.

## Public Scope

Version 1 includes Labs 00-06 and `harness/`. It excludes active MCP and agentic-security implementation work. The final section of the root README records that Version 2 work without adding its code or unpublished evidence.

## Design Thesis

Deterministic controls keep decision authority. Language models can classify, summarize, retrieve, or propose drafts, but their output is untrusted until a deterministic control or an authorized human reviewer validates it.

## Sanitized Real-World-Inspired Case

Lab 03 preserves the structure and lessons of a real-world review while removing identifiable systems, providers, domains, credentials, and deployment details. It is not a disclosure of the original application. Its evidence record must remain generic and safe to publish.

## Documentation Contract

Every lab README explains purpose, scope, safe use, evidence, limits, and its connection to the harness. Code uses English module docstrings and comments for non-obvious security decisions. Comments explain why, not syntax that is already clear from the code.
