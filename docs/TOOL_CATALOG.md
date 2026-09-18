# Tool Catalog

Every tool used in this project, grouped by role. For each: what it does, why it was chosen, what it is good for, and where its limits were observed. Results in this repository are evidence for a specific configuration and fixture — a tool marked as effective in one lab is not thereby approved for another use.

## Deterministic Code Analysis (SAST)

### Bandit
- **What it is:** Static analyzer for Python based on AST patterns.
- **Why:** It is fast, free of false certainty, and the natural deterministic anchor against which AI-assisted analysis can be compared.
- **Good at:** Hardcoded-credential patterns, weak crypto, `eval`, `shell=True`, `assert`, and other syntactic findings near the sink.
- **Not for:** Following data flow across functions or files; it cannot confirm exploitability, only pattern presence.
- **Used in Labs:** 02, 06, and the harness (`capabilities/bandit_capability.py`).

### Semgrep OSS
- **What it is:** Rule-based pattern matching with local taint modes.
- **Why:** Complements Bandit with user-written rules; one of the academic-hybrid building blocks (SAST + LLM triage).
- **Good at:** Precise local rules for concrete patterns; in the local-flow benchmark it reached the highest local-detection F1 (0.92) on the 25-case corpus.
- **Not for:** Inter-file taint tracking in the OSS configuration used here; that capability was not measured and is not claimed.
- **Used in Lab:** 06 (local-flow benchmark).

### CodeQL
- **What it is:** Semantic code analysis with queryable data-flow graphs.
- **Why:** It is the standard tool that can actually evidence a source-to-sink flow across modules.
- **Good at:** It was the only tool that proved the three-file `routes -> services -> db` flow in the benchmark via SARIF.
- **Not for:** Automatic full framework coverage: it missed flows arriving through `Request.query_params` in the corpus; low recall (0.15) in this evaluation. Run times must be measured before CI adoption.
- **Used in Lab:** 06 (local-flow benchmark).

## Model Artifact Supply Chain

### ModelScan
- **What it is:** Static scanner for malicious payloads inside serialized model artifacts (pickle, Keras formats).
- **Why:** Deterministic detection of dangerous opcodes, mirroring dependency scanning patterns already familiar from classic DevSecOps.
- **Good at:** Detecting `os.system`-style payloads on scan, with deterministic results and no LLM uncertainty.
- **Not for:** Proving a `safetensors` file is safe — it skips the format by design; and it cannot detect tampering after scanning (that is what signing is for).
- **Used in Lab:** 01.

### safetensors
- **What it is:** A serialization format with no code execution path.
- **Why:** Designing out the vulnerability class, instead of scanning for it.
- **Good at:** Prevention by construction — there is no "opcodes" question to answer.
- **Not for:** Integrity or provenance on its own; the format cannot tell whether the bytes were altered after conversion.
- **Used in Lab:** 01.

### Cosign (Sigstore)
- **What it is:** Artifact signing and verification.
- **Why:** Answers the question neither scanning nor format conversion can: "is this the exact artifact that was validated?"
- **Good at:** Detecting single-byte tampering; the public verification key can be published safely.
- **Not for:** Here it runs in key-based mode for simplicity; a real pipeline would use Sigstore keyless/OIDC, which this lab does not demonstrate.
- **Used in Lab:** 01.

### OPA (Rego)
- **What it is:** Policy-as-code evaluation; here, CLI evaluation of an admission rule.
- **Why:** Encodes the gate that demo annotations on a deployment must report scanned + signed + safe-format.
- **Good at:** Clear, auditable deny-by-default policy logic.
- **Not for:** The policy evaluates submitter-provided annotations; it does not verify the Cosign bundle itself, and no Gatekeeper cluster is deployed. It is a policy-logic demonstration, not an enforceable admission control.
- **Used in Lab:** 01.

## Local AI Runtime

### Ollama
- **What it is:** Local inference engine for open-weight models (Llama, Qwen, and similar).
- **Why:** Keeps every experiment 100% local, with no paid APIs and no data leaving the machine.
- **Good at:** Fast GPU-backed inference for 7-9B models on consumer hardware.
- **Not for:** Reasoning-heavy or multi-step agentic tasks; every lab that tried confirmed the ceiling of local 7-9B models for complex reasoning.

### FastAPI
- **What it is:** Python web framework used to build the semantic-firewall proxy.
- **Why:** Minimal code, typed request/response models, easy local testing.
- **Not for:** The prototype endpoint has no authentication or rate limiting and must never be exposed to a network.

### Docker
- **What it is:** Container isolation used for Qdrant and for agentic-pentesting sandboxes.
- **Why:** Keeps attack-able targets separated from the host and reproducible.
- **Not for:** The labs do not harden production containers; isolation boundaries are local-lab grade.

### Qdrant
- **What it is:** Self-hosted vector database for the RAG experiments.
- **Why:** Mature self-hosted option; local with no managed-service dependency.
- **Good at:** Reproducing realistic semantic retrieval, including the poisoning attack.
- **Not for:** The lab does not configure production-grade deployment, authentication, or scaling.

### spaCy (via Presidio)
- **What it is:** The NLP engine behind PII entity recognition (English + Spanish models).
- **Good at:** Off-the-shelf multilingual NER.
- **Limits observed:** False positives on Spanish greetings and on field labels like `Phone:`; confidence scales differ per recognizer, so a single global threshold does not work. This drove the combined low-threshold + denylist + field-label rule.

## LLM Safety Controls

### Llama Prompt Guard 2 (Meta)
- **What it is:** A small dedicated classifier for prompt injection.
- **Why:** The canonical first layer for a semantic firewall; runs on CPU so it does not compete for GPU.
- **Good at:** Direct injections, roleplay jailbreaks, multilingual attacks. The official gated model outperformed the ONNX replica (9/11 vs 6/11 on the local adversarial set).
- **Not for:** Encoded payloads (Base64, character-by-character spelling), third-person "editorial convention" phrasing, or anything where the attack only becomes visible after decoding. It is a classifier, never a guarantee.
- **Used in Labs:** 00, 04, and the harness.

### Microsoft Presidio
- **What it is:** PII detection and anonymization.
- **Why:** Industry-standard, runs locally, multilingual configurable.
- **Good at:** Structured anonymization with recognizer-level control.
- **Not for:** Zero-error claims; statistical NER always has false positives and false negatives, so the project treats its output as a control signal, not proof of safe data.

## LLM Red Teaming and Evaluation

### Garak (NVIDIA)
- **What it is:** LLM vulnerability scanner with a library of probes.
- **Why:** Industry-standard adversarial evidence instead of hand-written scripts alone.
- **Good at:** Volume (512-sample encoding campaigns) and structured JSONL reporting.
- **Limits observed:** Detectors are calibrated to English by default — the lab had to write a Spanish refusal detector; and a corrupted/aborted run is unusable evidence. An earlier indirect-injection percentage was retracted because its source file could not be recovered.
- **Used in Labs:** 04, 04a, 04b, and the harness (synthetic staging target only).

### Giskard
- **What it is:** LLM evaluation framework with scenario generation and JUnit output.
- **Good at:** Versioned test suites that replay deterministically; phase-A evaluation also caught that the firewall's output filter over-blocked on detected PII (false positives on benign controls), which was then fixed.
- **Not for:** Value depends on having CI and (for the generative mode) an LLM judge; judged only useful once CI exists.
- **Used in Lab:** 04b.

### PyRIT (Microsoft)
- **What it is:** Adversarial campaign framework with multi-turn attack orchestration.
- **Good at:** Adaptive multi-turn evaluation design.
- **Limit observed:** It shows no differentiated value against the stateless `/chat` endpoint; its distinctive capability requires a target with conversation memory. Deferred until such a target exists.

## AI-Assisted Code Analysis

### Vulnhuntr (Protect AI)
- **What it is:** Zero-shot LLM vulnerability analysis over Python, with call-chain context expansion.
- **Why:** Represents the category "model that reasons about code" between a pattern-matching SAST and an agent that executes.
- **Good at:** Producing narrative data-flow reasoning and, with a code-specialized model, valid structured JSON.
- **Limits observed:** Seven fixed vulnerability categories only; symbol-finding required exact literal text and failed on every local model until the relative-path root cause was diagnosed (upstream-fix study); findings remained advisory even after that fix, because semantic misclassification persisted.
- **Verdict in this project:** Advisory signal only, never blocking; the harness keeps it as optional `deep` profile.

### Strix
- **What it is:** Autonomous pentest agent that runs the target in a sandbox and requires a working PoC before reporting.
- **Why:** The strongest category tested — dynamic confirmation rather than static reasoning.
- **Good at:** With a frontier-class model it traced the three-file chain and confirmed a real SQL injection over HTTP with zero false positives in that run.
- **Limits observed:** Local 7-9B models failed completely (they narrated without acting). It is a per-engagement tool, not a per-PR gate, and its subscription-path quota made broad scans impractical.

## How These Pieces Fit

Deterministic tools (Bandit, Semgrep, CodeQL, ModelScan, Cosign, OPA) keep decision authority. Safety controls (Prompt Guard, Presidio) are layers, not verdicts. Red-team tooling (Garak, Giskard, PyRIT) measures behavior but its raw verdicts are untrusted until reviewed. AI-assisted analysis (Vulnhuntr, Strix) adds coverage where patterns alone cannot reach — always advisory, always human-reviewed.
