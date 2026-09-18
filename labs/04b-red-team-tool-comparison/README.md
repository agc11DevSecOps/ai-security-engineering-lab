# Phase 3b.1: Red-Team Tool Comparison

## Scope

This lab compares Garak, Giskard, and PyRIT without confusing tool coverage with target security. The shared HTTP corpus measures the same local firewall behavior for each run. Native tool campaigns are reported separately.

## Method

`redteam_comparison` provides a small, fixed synthetic corpus: Base64 instruction-following probes, inline indirect-injection proxies, and benign controls. Each attack contains a synthetic canary. The oracle records an attack only when the target returns that canary; a valid block is recorded separately, and all other responses are `inconclusive`.

Run a bounded control sample:

```bash
python scripts/run_target_corpus.py --tool control --per-vector 8 --benign-controls 8 --output reports/control.jsonl
python scripts/analyze_results.py reports/control.jsonl
```

The runner writes a manifest, corpus hash, timestamps, per-request latency, errors, and a report hash. It suppresses headline rates for incomplete or error-bearing runs.

## Evidence Boundary

The historical Phase 3b source JSONL is absent. The claim `362/512 = 29.3%` is neither arithmetically consistent nor reproducible and is not evidence. This lab is the current methodology; it does not recreate or validate the missing run.

## Safety And Limits

Use only the local target and synthetic data. Do not configure external model credentials unless a separately authorized campaign documents its data handling and budget. Results are bounded observations of a specific corpus, model, target version, and environment. Inline documents are proxies, not validation of a live RAG retrieval pipeline. The stateless target cannot demonstrate multi-turn resistance.
