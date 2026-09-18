"""Run Vulnhuntr for each discovered Python file and normalize its output.

Explicit file selection avoids relying on framework-based auto-discovery. The
executable defaults to ``vulnhuntr`` from the active environment.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.finding import Finding
from core.path_utils import normalize_path

DEFAULT_MODEL = "qwen2.5-coder:7b-instruct"
DEFAULT_VULNHUNTR_BIN = "vulnhuntr"


def discover_python_files(target_dir: str, exclude_dirs: set[str] | None = None) -> list[Path]:
    """Find Python files while excluding generated and tool-local directories."""
    if exclude_dirs is None:
        exclude_dirs = {".venv", "venv", "__pycache__", ".git", "node_modules",
                        "migrations", "tests", "test"}

    target_path = Path(target_dir).resolve()
    files = []
    for py_file in target_path.rglob("*.py"):
        if any(part in exclude_dirs for part in py_file.parts):
            continue
        files.append(py_file)
    return files


def run_vulnhuntr_on_file(target_dir: str, file_relative: str, model: str = DEFAULT_MODEL,
                            vulnhuntr_bin: str = DEFAULT_VULNHUNTR_BIN, timeout: int = 300) -> dict | None:
    """Run Vulnhuntr for one file and return raw JSON, or ``None`` on failure."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    env = {"OLLAMA_MODEL": model}
    import os
    full_env = os.environ.copy()
    full_env.update(env)

    try:
        result = subprocess.run(
            [vulnhuntr_bin, "-r", str(target_dir), "-a", file_relative,
             "-l", "ollama", "--json", output_path],
            capture_output=True, text=True, timeout=timeout, env=full_env,
            cwd=str(target_dir),
        )
        with open(output_path) as f:
            return json.load(f)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"  [WARN] Vulnhuntr failed for {file_relative}: {e}", file=sys.stderr)
        return None
    finally:
        Path(output_path).unlink(missing_ok=True)


def run_vulnhuntr(target_dir: str, model: str = DEFAULT_MODEL) -> list[Finding]:
    target_path = Path(target_dir).resolve()
    files = discover_python_files(target_dir)
    print(f"Discovered Python files: {len(files)}")

    all_findings = []
    for py_file in files:
        rel = py_file.relative_to(target_path)
        print(f"  Analyzing: {rel}")
        data = run_vulnhuntr_on_file(str(target_path), str(rel), model=model)
        if not data:
            continue

        for finding in data.get("findings", []):
            file_path = finding.get("file_path", str(py_file))
            all_findings.append(Finding(
                source="vulnhuntr",
                file_path=normalize_path(file_path, str(target_path)),
                line=None,  # Vulnhuntr does not always provide an exact line.
                severity=finding.get("severity", "MEDIUM").upper(),
                rule_id=finding.get("rule_id", ""),
                description=finding.get("analysis", finding.get("description", "")),
                confidence=(finding.get("confidence_score", 5) / 10.0) if finding.get("confidence_score") else None,
                cwe=finding.get("cwe_id"),
                poc=finding.get("poc"),
                extra={"title": finding.get("title", "")},
            ))
    return all_findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../target"
    findings = run_vulnhuntr(target)
    print(f"\nFindings found: {len(findings)}\n")
    for f in findings:
        print(f"[{f.severity}] {f.rule_id} - {f.file_path}")
        print(f"  {f.description[:150]}")
        print(f"  confidence={f.confidence}, cwe={f.cwe}")
