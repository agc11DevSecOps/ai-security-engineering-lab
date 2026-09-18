# Phase 4b: Vulnhuntr Evaluation

## Scope

This lab evaluates Vulnhuntr with local models on deliberately vulnerable Python fixtures and compares its output with Bandit. The goal is to understand tool behavior, not to endorse a scanner or establish a production gate.

## Observations

The tested models could produce valid structured output but missed fixture categories outside Vulnhuntr's fixed schema and sometimes assigned incorrect vulnerability types with high confidence. A multi-file scenario also showed that incomplete context can lead to speculation. These findings support using deterministic SAST and human review alongside, not instead of, LLM-assisted analysis.

## Safety And Reproducibility

Use only local, intentionally vulnerable fixtures. Do not scan private repositories or submit their source to a model service without authorization. Record the target revision, dependency and model versions, prompts, commands, raw reports, logs, errors, and configuration. Results are bounded observations of these fixtures and do not measure general recall or precision.

## Boundary With Follow-On Work

The hybrid pipeline and upstream diagnosis are separate studies. This README does not claim an upstream fix or a general solution for multi-file analysis.
