"""Generate evidence-cited advisory STRIDE threats from sanitized inputs.

Evidence citations reduce unsupported claims but do not replace independent
review. Generated threats are drafts, not verified security findings.
"""
import json
import sys
import time

import requests

LOCAL_MODEL_HOST = "http://localhost:11434"
DIAGRAM_PATH = "diagrams/architecture.mmd"
EVIDENCE_PATH = "diagrams/evidence_record.md"
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
                    "evidence_citation": {"type": "string"},
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "mitigation": {"type": "string"},
                },
                "required": ["component", "stride_category", "description", "evidence_citation", "severity", "mitigation"],
            },
        },
    },
    "required": ["threats"],
}


def load_context():
    with open(DIAGRAM_PATH) as file:
        diagram = file.read()
    with open(EVIDENCE_PATH) as file:
        evidence = file.read()
    return diagram, evidence


def build_prompt(diagram, evidence):
    return f"""You are a senior security engineer preparing an advisory STRIDE threat-model draft from bounded, reviewed evidence.

ARCHITECTURE DESCRIPTION:
{diagram}

SANITIZED EVIDENCE RECORD:
{evidence}

STRICT RULES:
1. Every threat MUST be based on an explicit fact in the evidence record. In "evidence_citation", quote the exact supporting evidence line.
2. Do not create a threat for an explicitly documented expected design decision.
3. Do not claim a managed secret reference exposes a secret value.
4. Pay particular attention to explicit inconsistencies, such as declared-but-unused configuration or differing data handling across processing steps.
5. Do not invent components or mechanisms not present in the architecture description or evidence record.
6. Treat all generated items as advisory drafts, not verified findings.

Generate 8 to 15 specific, evidence-supported threats. Respond ONLY with valid JSON:
{{
  "threats": [
    {{"component": "...", "stride_category": "Spoofing", "description": "...", "evidence_citation": "exact evidence line", "severity": "HIGH", "mitigation": "..."}}
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


def validate(threats):
    """Return narrow regression signals that require reviewer interpretation."""
    all_text = " ".join(
        f"{threat.get('component', '')} {threat.get('description', '')} {threat.get('mitigation', '')} {threat.get('evidence_citation', '')}".lower()
        for threat in threats
    )
    descriptions = [threat.get("description", "").lower() for threat in threats]
    return {
        "unexpected_authentication_claim": any("authentication" in text and "no " in text for text in descriptions),
        "unsupported_secret_exposure_claim": any("secret" in text and "file" in text and "managed" not in text for text in descriptions),
        "found_rate_limit_issue": any(keyword in all_text for keyword in ["hardcode", "not read", "not used", "declared", "config", "multiple instances"]) and "limit" in all_text,
        "found_data_handling_inconsistency": ("message" in all_text or "request record" in all_text) and ("notification" in all_text or "email" in all_text) and any(keyword in all_text for keyword in ["unencrypted", "plaintext", "not encrypted"]),
    }


def main():
    model = sys.argv[1] if len(sys.argv) > 1 else "local-instruct-model"
    diagram, evidence = load_context()
    print(f"=== Generating evidence-cited advisory STRIDE draft with: {model} ===")
    raw, elapsed = call_local_model(model, build_prompt(diagram, evidence))

    safe_name = model.replace(":", "_").replace(".", "_")
    output_path = f"stride_output/stride_v2_{safe_name}.json"
    with open(output_path, "w") as file:
        file.write(raw)
    try:
        threats = json.loads(raw).get("threats", [])
    except json.JSONDecodeError as error:
        print(f"FAIL: Invalid JSON: {error}")
        return

    results = validate(threats)
    print(f"Time: {elapsed:.1f}s | Generated threats: {len(threats)}")
    print("\n=== Regression-signal validation ===")
    print(f"Unexpected authentication claim: {'YES' if results['unexpected_authentication_claim'] else 'NO'}")
    print(f"Unsupported managed-secret exposure claim: {'YES' if results['unsupported_secret_exposure_claim'] else 'NO'}")
    print("\n=== Review-topic signals ===")
    print(f"Identified inconsistent rate limiting: {'YES' if results['found_rate_limit_issue'] else 'NO'}")
    print(f"Identified inconsistent data handling: {'YES' if results['found_data_handling_inconsistency'] else 'NO'}")
    print("\n=== Generated advisory threats ===")
    for threat in threats:
        print(f"[{threat.get('severity')}] {threat.get('stride_category')} - {threat.get('component')}")
        print(f"  {threat.get('description')}")
        print(f"  Cited evidence: {threat.get('evidence_citation')}")
        print(f"  Mitigation: {threat.get('mitigation')}")
        print("-" * 70)


if __name__ == "__main__":
    main()
