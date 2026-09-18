"""Retrieve evidence deterministically before an advisory model comparison.

Lexical retrieval bounds model context but is not semantic retrieval or evidence
validation. A reviewer must validate all output against the source record.
"""
import json
import re
import sys

import requests

LOCAL_MODEL_HOST = "http://localhost:11434"
EVIDENCE_PATH = "diagrams/evidence_record.md"
SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE"]},
        "explanation": {"type": "string"},
    },
    "required": ["verdict", "explanation"],
}
STOPWORDS = {"the", "and", "for", "with", "that", "this", "from", "are", "was", "not", "but", "into", "than", "when"}


def load_evidence_lines():
    with open(EVIDENCE_PATH) as file:
        return [line.strip() for line in file if line.strip()]


def extract_keywords(text):
    return [word for word in re.findall(r"[a-z']+", text.lower()) if word not in STOPWORDS and len(word) > 3]


def retrieve_relevant_lines(threat_description, evidence_lines, top_n=5):
    keywords = extract_keywords(threat_description)
    scored = []
    for line in evidence_lines:
        score = sum(1 for keyword in keywords if keyword in line.lower())
        if score:
            scored.append((score, line))
    scored.sort(key=lambda item: -item[0])
    return [line for _, line in scored[:top_n]]


def build_prompt(relevant_lines, threat):
    evidence = "\n".join(f"- {line}" for line in relevant_lines) if relevant_lines else "(no keyword-matched evidence)"
    return f"""You are an evidence reviewer comparing an advisory statement with relevant, deterministically retrieved evidence.

RETRIEVED EVIDENCE:
{evidence}

THREAT STATEMENT:
"{threat.get('description')}"

Return SUPPORTED when a fragment confirms or is consistent with the statement, CONTRADICTED when a fragment states the opposite central fact, or INSUFFICIENT_EVIDENCE when no fragment addresses the topic. This is an advisory comparison, not a verified finding.

Respond ONLY with JSON:
{{"verdict": "SUPPORTED|CONTRADICTED|INSUFFICIENT_EVIDENCE", "explanation": "brief explanation citing relevant evidence"}}"""


def call_local_model(model, prompt):
    response = requests.post(f"{LOCAL_MODEL_HOST}/api/generate", json={"model": model, "prompt": prompt, "stream": False, "format": SCHEMA, "options": {"temperature": 0}}, timeout=120)
    response.raise_for_status()
    return response.json()["response"]


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "local-instruct-model"
    input_path = sys.argv[2]
    with open(input_path) as file:
        threats = json.load(file)["threats"]
    evidence_lines = load_evidence_lines()
    print(f"=== Evidence comparison with lexical retrieval: {len(threats)} threats with {model} ===\n")
    results = []
    for index, threat in enumerate(threats, start=1):
        relevant = retrieve_relevant_lines(threat.get("description", ""), evidence_lines)
        raw = call_local_model(model, build_prompt(relevant, threat))
        try:
            comparison = json.loads(raw)
        except json.JSONDecodeError:
            comparison = {"verdict": "PARSE_ERROR", "explanation": raw[:200]}
        results.append({**threat, "retrieved_evidence": relevant, "fact_check": comparison})
        print(f"[{index}] {threat.get('component')} - {threat.get('stride_category')}")
        print(f"    Threat: {threat.get('description')[:80]}...")
        print(f"    Retrieved evidence (top two): {relevant[:2]}")
        print(f"    Advisory verdict: {comparison.get('verdict')}")
        print(f"    Explanation: {comparison.get('explanation')}")
        print("-" * 70)
    output_path = input_path.replace(".json", "_factchecked_v4.json")
    with open(output_path, "w") as file:
        json.dump({"threats": results}, file, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
