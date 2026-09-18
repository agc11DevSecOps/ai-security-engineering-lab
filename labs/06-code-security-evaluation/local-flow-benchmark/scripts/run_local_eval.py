#!/usr/bin/env python3
"""Ejecuta Bandit, Semgrep OSS y CodeQL localmente contra el mismo benchmark."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from score import parse_bandit, parse_codeql, parse_semgrep


ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
WORK = ROOT / "work"
CONFIG = ROOT / "config" / "semgrep-sqli.yml"
DEFAULT_CODEQL = "codeql"
DEFAULT_SEMGREP = "semgrep"


def tool_path(environment_variable: str, default: str) -> str:
    return os.environ.get(environment_variable, default)


def version(command: str) -> str | None:
    if not shutil.which(command) and not Path(command).exists():
        return None
    version_argument = "version" if Path(command).name == "codeql" else "--version"
    result = subprocess.run([command, version_argument], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return (result.stdout or result.stderr).strip()


def run(command: list[str]) -> tuple[str, str, int, float]:
    started = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode, round(time.monotonic() - started, 3)


def run_bandit(case: str, target: Path, binary: str) -> dict:
    output = REPORTS / f"bandit_{case}.json"
    stdout, stderr, returncode, duration = run([binary, "-r", str(target), "-f", "json"])
    output.write_text(stdout)
    status = "success" if returncode in {0, 1} and stdout else "failed"
    result = parse_bandit(output) if status == "success" else None
    return {"tool": "bandit", "case": case, "status": status, "duration_seconds": duration, "returncode": returncode, "stderr": stderr, "raw_report": str(output.relative_to(ROOT)), "result": result}


def run_semgrep(case: str, target: Path, binary: str) -> dict:
    output = REPORTS / f"semgrep_{case}.json"
    stdout, stderr, returncode, duration = run([binary, "scan", "--config", str(CONFIG), "--json", "--quiet", str(target)])
    output.write_text(stdout)
    status = "success" if returncode in {0, 1} and stdout else "failed"
    result = parse_semgrep(output) if status == "success" else None
    return {"tool": "semgrep", "case": case, "status": status, "duration_seconds": duration, "returncode": returncode, "stderr": stderr, "raw_report": str(output.relative_to(ROOT)), "result": result}


def run_codeql(case: str, target: Path, binary: str) -> dict:
    database = WORK / "codeql" / case
    output = REPORTS / f"codeql_{case}.sarif"
    database.parent.mkdir(parents=True, exist_ok=True)
    if database.exists():
        shutil.rmtree(database)
    create_stdout, create_stderr, create_returncode, create_duration = run([binary, "database", "create", str(database), "--language=python", f"--source-root={target}", "--overwrite"])
    if create_returncode != 0:
        return {"tool": "codeql", "case": case, "status": "failed", "duration_seconds": create_duration, "returncode": create_returncode, "stderr": create_stderr, "raw_report": None, "result": None}

    analyze_stdout, analyze_stderr, analyze_returncode, analyze_duration = run([binary, "database", "analyze", str(database), "codeql/python-queries:codeql-suites/python-security-and-quality.qls", "--format=sarif-latest", f"--output={output}"])
    status = "success" if analyze_returncode == 0 and output.exists() else "failed"
    result = parse_codeql(output) if status == "success" else None
    return {"tool": "codeql", "case": case, "status": status, "duration_seconds": round(create_duration + analyze_duration, 3), "returncode": analyze_returncode, "stderr": create_stderr + analyze_stderr, "raw_report": str(output.relative_to(ROOT)) if output.exists() else None, "result": result}


def main() -> None:
    REPORTS.mkdir(exist_ok=True)
    codeql = tool_path("CODEQL_BIN", DEFAULT_CODEQL)
    semgrep = tool_path("SEMGREP_BIN", DEFAULT_SEMGREP)
    bandit = tool_path("BANDIT_BIN", "bandit")
    tools = {"codeql": codeql, "semgrep": semgrep, "bandit": bandit}
    missing = [name for name, binary in tools.items() if version(binary) is None]
    if missing:
        raise SystemExit(f"Herramientas no disponibles: {', '.join(missing)}")

    observations = []
    for target in sorted((ROOT / "fixtures").glob("case-*")):
        if not target.is_dir():
            continue
        case = target.name
        observations.append(run_bandit(case, target, bandit))
        observations.append(run_semgrep(case, target, semgrep))
        observations.append(run_codeql(case, target, codeql))

    payload = {"tool_versions": {name: version(binary) for name, binary in tools.items()}, "observations": observations}
    raw_path = REPORTS / "raw_results.json"
    raw_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
