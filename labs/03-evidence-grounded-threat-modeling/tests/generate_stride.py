"""Generate an advisory STRIDE draft from a sanitized architecture description.

Structured output constrains categories, but generated threats remain untrusted
drafts. The deterministic checks are review signals, not verified findings.
"""
import json
import sys
import time

import requests

LOCAL_MODEL_HOST = "http://localhost:11434"
DIAGRAM_PATH = "diagrams/architecture.mmd"

STRIDE_CATEGORIES = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
]

SCHEMA = {
    "type": "object",
    "properties": {
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "component": {"type": "string"},
                    "stride_category": {"type": "string", "enum": STRIDE_CATEGORIES},
                    "description": {"type": "string"},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "mitigation": {"type": "string"},
                },
                "required": ["component", "stride_category", "description", "severity", "mitigation"],
            },
        },
    },
    "required": ["threats"],
}


def load_diagram():
    with open(DIAGRAM_PATH) as file:
        return file.read()


def build_prompt(diagram):
    return f"""You are a senior security engineer preparing an advisory STRIDE threat-model draft.

Here is a sanitized reference application's architecture description in Mermaid format:

{diagram}

Analyze each component and data flow. For each supported risk, classify it as Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, or Elevation of Privilege.

Requirements:
- Base each threat on a specific diagram detail. Do not generate generic STRIDE entries without a concrete basis.
- Identify explicit inconsistencies, such as protection applied in one processing step but not another or declared configuration that is not applied.
- Generate 8 to 15 specific, actionable threats.
- Treat this as an advisory draft. Do not claim that a threat is verified.

Respond ONLY with valid JSON in this form:
{{
  "threats": [
    {{"component": "component or flow name", "stride_category": "Spoofing", "description": "specific threat description", "severity": "HIGH", "mitigation": "specific mitigation"}}
  ]
}}"""


def call_local_model(model, prompt):
    started = time.time()
    response = requests.post(
        f"{LOCAL_MODEL_HOST}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "format": SCHEMA, "options": {"temperature": 0}},
        timeout=300,
    )
    response.raise_for_status()
    return response.json()["response"], time.time() - started


def validate_review_topics(threats):
    """Check for two known review topics without treating either as verified."""
    all_text = " ".join(
        f"{threat.get('component', '')} {threat.get('description', '')} {threat.get('mitigation', '')}".lower()
        for threat in threats
    )
    rate_limit_keywords = ["rate limit", "rate_limit", "hardcoded", "not used", "not read", "declared", "in-memory", "multiple instances", "scaling"]
    data_handling_keywords = ["plaintext", "unencrypted", "not encrypted", "partial encryption", "notification", "email"]
    return (
        any(keyword in all_text for keyword in rate_limit_keywords),
        any(keyword in all_text for keyword in data_handling_keywords),
    )


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "local-instruct-model"
    prompt = build_prompt(load_diagram())
    print(f"=== Generating advisory STRIDE draft with: {model} ===")
    raw, elapsed = call_local_model(model, prompt)

    safe_name = model.replace(":", "_").replace(".", "_")
    output_path = f"stride_output/stride_{safe_name}.json"
    with open(output_path, "w") as file:
        file.write(raw)

    try:
        threats = json.loads(raw).get("threats", [])
    except json.JSONDecodeError as error:
        print(f"FAIL: Invalid JSON: {error}")
        return

    by_category = {}
    for threat in threats:
        category = threat.get("stride_category", "?")
        by_category[category] = by_category.get(category, 0) + 1
    print(f"Time: {elapsed:.1f}s | Generated threats: {len(threats)}")
    print(f"STRIDE category distribution: {by_category}")

    found_rate_limit, found_data_handling = validate_review_topics(threats)
    print("\n=== Review-topic signals ===")
    print(f"Identified inconsistent rate limiting: {'YES' if found_rate_limit else 'NO'}")
    print(f"Identified inconsistent data handling: {'YES' if found_data_handling else 'NO'}")
    print("\n=== Generated advisory threats ===")
    for threat in threats:
        print(f"[{threat.get('severity')}] {threat.get('stride_category')} - {threat.get('component')}")
        print(f"  {threat.get('description')}")
        print(f"  Mitigation: {threat.get('mitigation')}")
        print("-" * 70)


if __name__ == "__main__":
    main()
