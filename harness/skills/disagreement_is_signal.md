# Runtime Rule: Disagreement Is Signal

## Guarantee

When two or more independent sources analyze the same location in the code and reach different conclusions, that disagreement is priority review signal, not noise to discard. Consolidation never silences one side.

## Origin

The hybrid pipeline experiments (Lab 06) showed deterministic and model-based analyzers disagreeing about the same line (one said SQLI, the other RCE). That conflict was more informative than silence from both.

## Where It Applies

`core/consolidator.py` groups findings by exact location and emits a `DISAGREEMENT` status when the same point carries multiple semantic categories across sources, keeping every input finding in the record.

## Regression Prevented

A future consolidator cannot collapse a disagreement into an "agreement" or a single unreviewed finding. Separation of roles holds: the consolidator records the conflict and its review priority, but never issues the final verdict.
