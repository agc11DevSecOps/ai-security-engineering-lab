"""Create an advisory natural-language triage from static-analysis findings.

Model output is untrusted and must be validated and reviewed before it informs
any merge gate, notification, or remediation decision.
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
    lines = []
    for r in findings:
        lines.append(
            f"- [{r['test_id']}] Native severity: {r['issue_severity']}/{r['issue_confidence']} "
            f"(line {r['line_number']}): {r['issue_text']}"
        )
    findings_block = "\n".join(lines)

    prompt = f"""You are a senior application security engineer performing advisory triage of Bandit static-analysis findings for a CI/CD pipeline.

Here are the raw scanner findings:

{findings_block}

Task:
1. Order these findings by real business impact. Do not merely repeat the scanner's native severity; consider the consequence of external exploitation.
2. For each finding, explain in one sentence why its relative priority is raised, lowered, or retained.
3. Clearly label each finding as "BLOCKING" (do not merge without review) or "TECHNICAL_DEBT" (remediate promptly but do not automatically block a release).

Respond in professional US English as a numbered list by priority (1 is most urgent). This is an advisory assessment, not an authorization decision."""
    return prompt


def call_ollama(prompt):
    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=180,
    )
    response.raise_for_status()
    return response.json()["response"]


def main():
    findings = load_findings()
    print(f"Loaded findings: {len(findings)}\n")

    prompt = build_prompt(findings)
    print("Querying the local model; this may take several seconds...\n")

    triage_result = call_ollama(prompt)
    print("=== MODEL-ASSISTED ADVISORY TRIAGE ===\n")
    print(triage_result)

    with open("sample_findings/triage_output.txt", "w") as f:
        f.write(triage_result)


if __name__ == "__main__":
    main()
