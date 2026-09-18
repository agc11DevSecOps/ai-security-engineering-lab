"""Reject publication hazards without executing lab code or reading binary artifacts."""

from __future__ import annotations

from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 1_000_000
EXCLUDED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".tools",
        ".venv",
        ".venv-eval",
        "__pycache__",
        "logs",
        "qdrant_storage",
        "reports",
        "reports_web",
        "strix_runs",
        "work",
    }
)
# Patterns are assembled at runtime so this checker does not flag its own source.
FORBIDDEN_TEXT = (
    "/home/" + "agc11/",  # original author's private home directory
    "sk-" + "live-",  # credential-shaped test token
    "Super" + "Secret123",  # password-shaped fixture value
    "SECURITY_CONTACT" + "_PLACEHOLDER=",  # config value, not the doc placeholder
)
TEXT_SUFFIXES = frozenset(
    {
        ".json",
        ".md",
        ".py",
        ".rego",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)


def _is_excluded(path: Path) -> bool:
    """Skip generated state before reading it; CI must not inspect local artifacts."""
    return any(part in EXCLUDED_DIRECTORY_NAMES for part in path.parts)


def _iter_text_files() -> list[Path]:
    """Return bounded, repository-relative text candidates in a stable order."""
    candidates: list[Path] = []
    for path in REPOSITORY_ROOT.rglob("*"):
        if not path.is_file() or _is_excluded(path.relative_to(REPOSITORY_ROOT)):
            continue
        if path.suffix not in TEXT_SUFFIXES or path.stat().st_size > MAX_TEXT_BYTES:
            continue
        candidates.append(path)
    return sorted(candidates)


def main() -> int:
    failures: list[str] = []
    for path in _iter_text_files():
        relative_path = path.relative_to(REPOSITORY_ROOT)
        content = path.read_text(encoding="utf-8", errors="replace")
        for forbidden in FORBIDDEN_TEXT:
            if forbidden in content:
                failures.append(f"{relative_path}: contains forbidden text {forbidden!r}")

    if failures:
        print("Repository publication checks failed:")
        print("\n".join(failures))
        return 1

    print("Repository publication checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
