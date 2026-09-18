# Runtime Rule: `think: false` for Reasoning Models

## Guarantee

For models that expose an intermediate reasoning phase before the final answer (and similar Ollama models), disabling the thinking mode (`think: false`) prevents intermediate reasoning from contaminating the expected structured output.

## Origin

During the zero-shot vulnerability-analysis experiments (Lab 06), the reasoning model left the final `response` field empty and wrote its output to `thinking` instead, breaking the JSON contract the adapter expected. Disabling thinking was a necessary — not sufficient — condition for valid output.

## Where It Applies

- Every LLM-backed capability must declare its exact generation configuration in the design record before implementation.
- This rule does not replace strict JSON schema validation; the two are orthogonal.

## Regression Prevented

An adapter that invokes a reasoning model without fixing `think: false` must not mark a result as complete when it was parsed from a stream polluted by intermediate reasoning.
