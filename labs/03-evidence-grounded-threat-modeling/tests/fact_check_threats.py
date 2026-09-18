"""Compare advisory threats with a sanitized evidence record.

The model returns an advisory comparison only. Reviewers must independently
validate the cited evidence and must not treat the verdict as a security decision.
"""
import json
import sys

import requests

LOCAL_MODEL_HOST = "http://localhost:11434"
EVIDENCE_PATH = "diagrams/evidence_record.md"
SCHEMA = {
    "type": "object",
    "properties": {
        "relevant_evidence_quote": {"type": "string"},
        "verdict": {"type": "string", "enum": ["SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"]},
        "explanation": {"type": "string"},
    },
    "required": ["relevant_evidence_quote", "verdict", "explanation"],
}


def load_evidence():
    with open(EVIDENCE_PATH) as file:
        return file.read()


def build_prompt(evidence, threat):
    return f"""You are an evidence reviewer. Compare one advisory threat statement with the bounded evidence record.

EVIDENCE RECORD:
{evidence}

THREAT STATEMENT:
"{threat.get('description')}"

First, copy the complete relevant prose sentence from the evidence record into "relevant_evidence_quote". Do not provide only a file or line reference. Then compare its meaning with the threat statement:
- SUPPORTED: the quoted evidence confirms or is consistent with the statement.
- CONTRADICTED: the quoted evidence states the opposite of the statement's central fact.
- INSUFFICIENT_EVIDENCE: the evidence record does not address the topic.

This is an advisory comparison, not a verified finding. Respond ONLY with JSON:
{{"relevant_evidence_quote": "complete evidence sentence", "verdict": "SUPPORTED|CONTRADICTED|INSUFFICIENT_EVIDENCE", "explanation": "brief explanation"}}"""


def call_local_model(model, prompt):
    response = requests.post(
        f"{LOCAL_MODEL_HOST}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "format": SCHEMA, "options": {"temperature": 0}},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["response"]


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "local-instruct-model"
    input_path = sys.argv[2]
    with open(input_path) as file:
        threats = json.load(file)["threats"]
    evidence = load_evidence()
    print(f"=== Evidence comparison: {len(threats)} threats with {model} ===\n")

    results = []
    for index, threat in enumerate(threats, start=1):
        raw = call_local_model(model, build_prompt(evidence, threat))
        try:
            comparison = json.loads(raw)
        except json.JSONDecodeError:
            comparison = {"verdict": "PARSE_ERROR", "relevant_evidence_quote": "", "explanation": raw[:200]}
        results.append({**threat, "fact_check": comparison})
        print(f"[{index}] {threat.get('component')} - {threat.get('stride_category')}")
        print(f"    Threat: {threat.get('description')[:80]}...")
        print(f"    Evidence quote: {comparison.get('relevant_evidence_quote', '')[:120]}")
        print(f"    Advisory verdict: {comparison.get('verdict')}")
        print(f"    Explanation: {comparison.get('explanation')}")
        print("-" * 70)

    output_path = input_path.replace(".json", "_factchecked.json")
    with open(output_path, "w") as file:
        json.dump({"threats": results}, file, indent=2, ensure_ascii=False)
    contradicted = [result for result in results if result["fact_check"].get("verdict") == "CONTRADICTED"]
    insufficient = [result for result in results if result["fact_check"].get("verdict") == "INSUFFICIENT_EVIDENCE"]
    print("\n=== Summary ===")
    print(f"Total: {len(results)} | Contradicted: {len(contradicted)} | Insufficient evidence: {len(insufficient)}")


if __name__ == "__main__":
    main()
