# Runtime Rule: Strict JSON Schema

## Guarantee

When a capability relies on a model to produce structured data, it must force a strict output format plus an explicit JSON Schema and validate the response before using it. A prompt instruction alone is not a contract.

## Origin

During advisory-triage experiments (Lab 02), asking the model to "return JSON" without an enforced format let the LLM round output to free text or invent fields. The fix was `format: json` plus an explicit schema, validated in Python before consuming the result.

## Where It Applies

- Never build a `Finding` from unvalidated text.
- Adapter normalizers (e.g. `BanditCapability`) parse strictly and reject malformed output.

## Regression Prevented

No normalized finding may originate from missing, truncated, or schema-violating JSON. Invalid output returns a `MALFORMED_TOOL_OUTPUT` status, not a silent finding.
