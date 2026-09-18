# hybrid_scan

## Scope

`hybrid_scan` is an experimental Python CLI. It runs Bandit and optionally Vulnhuntr, converts output to a common `Finding` format, and writes a consolidated JSON report. It is not a CI gate or an exploitability verifier.

## Usage

```bash
python hybrid_scan.py --target /path/to/python-project --output reports/
```

Use `--skip-vulnhuntr` to run Bandit only and `--model` to choose the local Vulnhuntr model.

## Safety And Limits

Run against a disposable copy of a target. Vulnhuntr may be slow and may write files in the target directory. Treat all model output as untrusted and require human review before any action. A zero Vulnhuntr count can mean no finding, a skipped scan, a timeout, or a failure; it is not evidence of safety.

## Reproducibility

Record the target revision, tool and model versions, commands, configuration, raw scanner output, and failures. Correlation is limited to normalized file and category, not source-to-sink proof. Results are bounded observations for the scanned target.
