"""Create and validate schema-constrained advisory triage for Bandit findings.

The schema protects output structure only. The model's prioritization must be
compared with source findings and reviewed before a security decision is made.
"""

import json
import sys
import time

import requests

OLLAMA_HOST = "http://localhost:11434"
FINDINGS_PATH = "sample_findings/bandit_raw.json"

SCHEMA = {
    "type": "object",
    "properties": {
        "triage": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "test_id": {"type": "string"},
                    "priority_rank": {"type": "integer"},
                    "category": {"type": "string", "enum": ["BLOQUEANTE", "DEUDA_TECNICA"]},
                    "reasoning": {"type": "string"}
                },
                "required": ["test_id", "priority_rank", "category", "reasoning"]
            }
        }
    },
    "required": ["triage"]
}

def load_findings():
    with open(FINDINGS_PATH) as f:
        return json.load(f)["results"]

def build_prompt(findings):
    items = [{"test_id": r["test_id"], "native_severity": r["issue_severity"],
              "native_confidence": r["issue_confidence"], "line": r["line_number"],
              "description": r["issue_text"]} for r in findings]
    return (
        "You are a senior application security engineer performing advisory triage "
        "of Bandit static-analysis findings.\n\nFindings:\n"
        + json.dumps(items, indent=2, ensure_ascii=False)
        + "\n\nUse EXACTLY the same test_id values, each once, without inventing or "
        "duplicating identifiers. category must be only BLOQUEANTE or "
        "DEUDA_TECNICA; these are fixed machine-readable values. Assess real "
        "business impact rather than repeating native severity. Read the issue "
        "text carefully: if it says use X instead of Y, Y is the unsafe function. "
        "Respond with advisory analysis in professional US English."
    )

def call_ollama(model, prompt):
    t0 = time.time()
    r = requests.post(OLLAMA_HOST + "/api/generate", json={
        "model": model, "prompt": prompt, "stream": False,
        "format": SCHEMA, "options": {"temperature": 0}
    }, timeout=300)
    r.raise_for_status()
    return r.json()["response"], time.time() - t0

def validate(findings, parsed):
    orig = set(r["test_id"] for r in findings)
    items = parsed.get("triage", [])
    counts = {}
    for i in items:
        tid = i.get("test_id")
        counts[tid] = counts.get(tid, 0) + 1
    errors = []
    for t in orig:
        if counts.get(t, 0) != 1:
            errors.append(t + ": " + str(counts.get(t, 0)) + " occurrence(s) (expected 1)")
    extra = set(counts.keys()) - orig
    if extra:
        errors.append("Unexpected identifiers: " + str(extra))
    b307 = None
    for i in items:
        if i.get("test_id") == "B307":
            b307 = i
    sem_err = None
    if b307 and b307.get("category") != "BLOQUEANTE":
        sem_err = "B307 categorized as " + str(b307.get("category")) + "; expected BLOQUEANTE"
    return errors, sem_err

def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "llama3.1:8b-instruct-q4_K_M"
    findings = load_findings()
    prompt = build_prompt(findings)
    print("=== " + model + " ===")
    raw, elapsed = call_ollama(model, prompt)
    safe = model.replace(":", "_").replace(".", "_")
    with open("sample_findings/triage_" + safe + ".json", "w") as f:
        f.write(raw)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        print("Invalid JSON: " + str(e))
        return
    errors, sem_err = validate(findings, parsed)
    print("Time: " + str(round(elapsed, 1)) + "s | Items: " + str(len(parsed.get("triage", []))) + "/" + str(len(findings)))
    print("Identifier errors: " + str(len(errors)))
    for e in errors:
        print("  - " + e)
    print("B307 semantic error: " + ("YES - " + sem_err if sem_err else "Not detected"))

if __name__ == "__main__":
    main()
