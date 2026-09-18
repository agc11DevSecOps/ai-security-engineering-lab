"""Flag inconsistent advisory evidence comparisons using two direct questions.

The two-question check is a review aid. It can itself be ambiguous and must not
be used as an automated fact-checking or security-decision mechanism.
"""
import json
import re
import sys

import requests

LOCAL_MODEL_HOST = "http://localhost:11434"
EVIDENCE_PATH = "diagrams/evidence_record.md"
BOOL_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string", "enum": ["YES", "NO"]}, "reasoning": {"type": "string"}},
    "required": ["answer", "reasoning"],
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


def ask_boolean(model, relevant_lines, question):
    evidence = "\n".join(f"- {line}" for line in relevant_lines) if relevant_lines else "(no relevant evidence retrieved)"
    prompt = f"""Evidence fragments:
{evidence}

Question: {question}

This is an advisory comparison, not a security decision. Respond ONLY with JSON:
{{"answer": "YES|NO", "reasoning": "brief explanation citing a fragment"}}"""
    response = requests.post(f"{LOCAL_MODEL_HOST}/api/generate", json={"model": model, "prompt": prompt, "stream": False, "format": BOOL_SCHEMA, "options": {"temperature": 0}}, timeout=120)
    response.raise_for_status()
    raw = response.json()["response"]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"answer": "ERROR", "reasoning": raw[:200]}


def cross_check(model, relevant_lines, description):
    supported = ask_boolean(model, relevant_lines, f'Do the evidence fragments support this statement? "{description}"')
    contradicted = ask_boolean(model, relevant_lines, f'Do the evidence fragments contradict this statement? "{description}"')
    supports = supported.get("answer") == "YES"
    contradicts = contradicted.get("answer") == "YES"
    if supports and not contradicts:
        verdict = "SUPPORTED"
    elif contradicts and not supports:
        verdict = "CONTRADICTED"
    elif not supports and not contradicts:
        verdict = "INSUFFICIENT_EVIDENCE"
    else:
        verdict = "INCONSISTENT_REVIEW_REQUIRED"
    return verdict, supported, contradicted


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "local-instruct-model"
    input_path = sys.argv[2]
    with open(input_path) as file:
        threats = json.load(file)["threats"]
    evidence_lines = load_evidence_lines()
    print(f"=== Cross-checking advisory threats: {len(threats)} with {model} ===\n")
    results = []
    for index, threat in enumerate(threats, start=1):
        description = threat.get("description", "")
        relevant = retrieve_relevant_lines(description, evidence_lines)
        verdict, support_check, contradiction_check = cross_check(model, relevant, description)
        results.append({**threat, "retrieved_evidence": relevant, "verdict": verdict, "support_check": support_check, "contradiction_check": contradiction_check})
        print(f"[{index}] {threat.get('component')} - {threat.get('stride_category')}")
        print(f"    Threat: {description[:80]}...")
        print(f"    Support check: {support_check.get('answer')} - {support_check.get('reasoning', '')[:80]}")
        print(f"    Contradiction check: {contradiction_check.get('answer')} - {contradiction_check.get('reasoning', '')[:80]}")
        print(f"    ADVISORY VERDICT: {verdict}")
        print("-" * 70)
    output_path = input_path.replace(".json", "_factchecked_v5.json")
    with open(output_path, "w") as file:
        json.dump({"threats": results}, file, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
