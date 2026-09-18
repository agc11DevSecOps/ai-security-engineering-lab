# Glossary for the Red-Team Comparison

| Term | Meaning here |
| --- | --- |
| Canary | A synthetic marker embedded in an attack case. If the target reproduces it, the attack succeeded. |
| Blocked | The target returned a recognized refusal or block response. |
| Inconclusive | Neither a canary nor a recognizable block. Never counted as secure. |
| Benign control | A normal request that must be allowed; used to measure false positives. |
| Oracle | The deterministic rule set that classifies a response as success, block, or inconclusive. |
| Native campaign | A scanner running its own probes; comparable over time, not across tools. |
| Common corpus | The identical case list sent to every adapter; the only basis for comparison. |
