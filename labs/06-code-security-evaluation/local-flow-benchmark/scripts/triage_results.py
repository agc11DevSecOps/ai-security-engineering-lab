#!/usr/bin/env python3
"""Evalua si un LLM local conserva findings deterministas sin alterar su deteccion."""
import json
import sys
import time
from pathlib import Path

import requests

from score import _contains_sqli


ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
OLLAMA_HOST = "http://localhost:11434"
SCHEMA = {
    "type": "object",
    "properties": {
        "triage": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "category": {"type": "string", "enum": ["BLOQUEANTE", "DEUDA_TECNICA"]},
                    "reasoning": {"type": "string"},
                },
                "required": ["finding_id", "category", "reasoning"],
            },
        }
    },
    "required": ["triage"],
}


def _location(result: dict) -> tuple[str, int | None]:
    location = result.get("locations", [{}])[0].get("physicalLocation", {})
    return location.get("artifactLocation", {}).get("uri", ""), location.get("region", {}).get("startLine")


def load_findings() -> list[dict]:
    findings = []
    observations = json.loads((REPORTS / "raw_results.json").read_text())["observations"]
    for observation in observations:
        if observation["status"] != "success" or not observation["result"]["detected"]:
            continue
        case = observation["case"]
        data = json.loads((ROOT / observation["raw_report"]).read_text())
        if observation["tool"] == "bandit":
            for result in data.get("results", []):
                if result.get("test_id") == "B608":
                    findings.append({"finding_id": f"bandit:{case}:{result['test_id']}:{result['line_number']}", "scanner": "bandit", "rule": result["test_id"], "cwe": "CWE-89", "severity": result["issue_severity"], "description": result["issue_text"]})
        elif observation["tool"] == "semgrep":
            for result in data.get("results", []):
                if result.get("check_id", "").endswith("f4f.sqlite-string-concat-execute"):
                    findings.append({"finding_id": f"semgrep:{case}:{result['check_id']}:{result['start']['line']}", "scanner": "semgrep", "rule": result["check_id"], "cwe": "CWE-89", "severity": result["extra"]["severity"], "description": result["extra"]["message"]})
        elif observation["tool"] == "codeql":
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    if _contains_sqli(result):
                        _, line = _location(result)
                        findings.append({"finding_id": f"codeql:{case}:{result.get('ruleId')}:{line}", "scanner": "codeql", "rule": result.get("ruleId"), "cwe": "CWE-89", "severity": "ERROR", "description": result.get("message", {}).get("text", "")})
    return findings


def build_prompt(findings: list[dict]) -> str:
    return (
        "Eres un ingeniero de seguridad haciendo triage de findings SAST ya detectados. "
        "No determines si existe una vulnerabilidad: conserva exactamente cada finding_id una vez. "
        "Clasifica CWE-89 como BLOQUEANTE porque representa una SQL injection alcanzable por datos no confiables.\n\n"
        f"Findings:\n{json.dumps(findings, ensure_ascii=False, indent=2)}"
    )


def validate(findings: list[dict], response: dict) -> list[str]:
    expected = {finding["finding_id"] for finding in findings}
    items = response.get("triage", [])
    actual = [item.get("finding_id") for item in items]
    errors = []
    if set(actual) != expected:
        errors.append("Los finding_id no coinciden exactamente con la entrada.")
    if len(actual) != len(expected):
        errors.append("Hay finding_id perdidos o duplicados.")
    for item in items:
        if item.get("category") != "BLOQUEANTE":
            errors.append(f"{item.get('finding_id')} no preserva la prioridad BLOQUEANTE de CWE-89.")
    return errors


def main() -> None:
    model = sys.argv[1] if len(sys.argv) > 1 else "llama3.1:8b-instruct-q4_K_M"
    findings = load_findings()
    prompt = build_prompt(findings)
    started = time.monotonic()
    response = requests.post(OLLAMA_HOST + "/api/generate", json={"model": model, "prompt": prompt, "stream": False, "format": SCHEMA, "options": {"temperature": 0}}, timeout=300)
    response.raise_for_status()
    raw = response.json()["response"]
    parsed = json.loads(raw)
    errors = validate(findings, parsed)
    safe_model = model.replace(":", "_").replace(".", "_")
    output = {"model": model, "duration_seconds": round(time.monotonic() - started, 3), "input_findings": findings, "response": parsed, "validation_errors": errors}
    path = REPORTS / f"triage_{safe_model}.json"
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(output, ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
