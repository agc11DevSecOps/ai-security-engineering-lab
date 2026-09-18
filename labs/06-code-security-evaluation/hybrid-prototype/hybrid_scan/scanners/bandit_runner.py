"""Run Bandit and translate its JSON output into the common Finding schema."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.finding import Finding
from core.path_utils import normalize_path


def run_bandit(target_dir: str) -> list[Finding]:
    """Run Bandit recursively and return findings relative to ``target_dir``."""
    target_path = Path(target_dir).resolve()
    cwd = str(target_path.parent)

    result = subprocess.run(
        ["bandit", "-r", str(target_path), "-f", "json"],
        capture_output=True, text=True,
    )

    # Bandit returns exit code 1 for findings; fail only if it emits invalid JSON.
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Bandit did not return valid JSON: {e}\nstderr: {result.stderr}")

    findings = []
    for r in data.get("results", []):
        findings.append(Finding(
            source="bandit",
            file_path=normalize_path(r["filename"], str(target_path), cwd=cwd),
            line=r["line_number"],
            severity=r["issue_severity"].upper(),
            rule_id=r["test_id"],
            description=r["issue_text"],
            confidence=_confidence_to_float(r["issue_confidence"]),
            cwe=str(r.get("issue_cwe", {}).get("id", "")) if r.get("issue_cwe") else None,
            extra={"code_snippet": r.get("code", "")},
        ))
    return findings


def _confidence_to_float(bandit_confidence: str) -> float:
    mapping = {"LOW": 0.33, "MEDIUM": 0.66, "HIGH": 1.0}
    return mapping.get(bandit_confidence.upper(), 0.5)


if __name__ == "__main__":
    import sys as _sys
    target = _sys.argv[1] if len(_sys.argv) > 1 else "../target"
    findings = run_bandit(target)
    print(f"Findings found: {len(findings)}\n")
    for f in findings:
        print(f"[{f.severity}] {f.rule_id} - {f.file_path}:{f.line}")
        print(f"  {f.description}")
        print(f"  confidence={f.confidence}")
