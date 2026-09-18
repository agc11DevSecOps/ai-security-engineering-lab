# Reproducibility Guide

## Deterministic Repository Checks

Run these checks without models, credentials, or network access:

```bash
make check
make test
```

`make check` rejects common publication hazards, then compiles the tracked Python source. `make test` runs the standard-library test suites for the harness and the red-team comparison corpus.

## Model-Backed Experiments

Some labs require locally provisioned tools or models. They are optional and intentionally excluded from CI. Before running one, create an evidence record with the tool version, model revision, fixture hash, command, timestamp, and outcome.

Never provide a production credential, customer data, private document, or unreviewed external target to a lab script.

## Supported Baseline

The deterministic harness tests use Python 3.10 or later and the standard library. Individual labs declare their additional dependencies in local requirements or their README. A dependency file is not a production deployment manifest; verify upstream releases and hashes before installing tools.
