"""Request structured advisory triage with generic JSON output and temperature zero.

JSON parsing improves output handling but does not establish factual or security
correctness; validate the result against the source findings.
"""
import json
import requests

OLLAMA_HOST = "http://localhost:11434"
MODEL = "llama3.1:8b-instruct-q4_K_M"
FINDINGS_PATH = "sample_findings/bandit_raw.json"


def load_findings():
    with open(FINDINGS_PATH) as f:
        data = json.load(f)
    return data["results"]


def build_prompt(findings):
    items = [{
        "test_id": r["test_id"],
        "native_severity": r["issue_severity"],
        "native_confidence": r["issue_confidence"],
        "line": r["line_number"],
        "description": r["issue_text"],
    } for r in findings]

    return f"""You are a senior application security engineer performing advisory triage of Bandit static-analysis findings.

Input findings (JSON):
{json.dumps(items, indent=2, ensure_ascii=False)}

IMPORTANT: use EXACTLY the same "test_id" values shown above, each exactly once. Do not invent or duplicate identifiers.

For each finding, assess real business impact if an external attacker exploited it; do not merely repeat the native severity.

Respond ONLY with valid JSON, without additional text, in this exact form:
{{
  "triage": [
    {{"test_id": "B602", "priority_rank": 1, "category": "BLOQUEANTE", "reasoning": "brief explanation in US English"}}
  ]
}}

The "triage" array must contain EXACTLY {len(items)} items, one for each input test_id, ordered by priority_rank (1 is most urgent). This is advisory output only."""


def call_ollama(prompt):
    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False,
              "format": "json", "options": {"temperature": 0}},
        timeout=180,
    )
    response.raise_for_status()
    return response.json()["response"]


def main():
    findings = load_findings()
    print(f"Loaded findings: {len(findings)}\n")
    prompt = build_prompt(findings)
    print("Querying the local model with JSON output and temperature zero...\n")
    raw = call_ollama(prompt)

    with open("sample_findings/triage_output_v2.json", "w") as f:
        f.write(raw)

    try:
        parsed = json.loads(raw)
        print(f"JSON parsed successfully. {len(parsed.get('triage', []))} items.\n")
        for item in parsed.get("triage", []):
            print(f"[{item.get('priority_rank')}] {item.get('test_id')} - {item.get('category')}")
            print(f"    {item.get('reasoning')}")
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}")


if __name__ == "__main__":
    main()
