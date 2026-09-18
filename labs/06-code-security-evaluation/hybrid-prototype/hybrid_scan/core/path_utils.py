"""Normalize paths relative to the scanned project root."""
from pathlib import Path


def normalize_path(file_path: str, project_root: str, cwd: str | None = None) -> str:
    """Return ``file_path`` relative to ``project_root`` where possible.

    The scanner may return an absolute path, a path relative to its working
    directory, or a path already relative to the target root.
    """
    root = Path(project_root).resolve()
    path = Path(file_path)

    if path.is_absolute():
        resolved = path.resolve()
    else:
        base_cwd = Path(cwd).resolve() if cwd else Path.cwd()
        candidate_from_cwd = (base_cwd / path).resolve()
        candidate_from_root = (root / path).resolve()

        # Prefer the candidate that is actually inside the target root.
        if str(candidate_from_cwd).startswith(str(root)):
            resolved = candidate_from_cwd
        elif str(candidate_from_root).startswith(str(root)):
            resolved = candidate_from_root
        else:
            resolved = candidate_from_cwd

    try:
        rel = resolved.relative_to(root)
    except ValueError:
        return str(resolved)

    return str(rel).replace("\\", "/")


if __name__ == "__main__":
    root = "/tmp/sample-target"
    cwd_parent = "/tmp"

    tests = [
        ("target/db/repository.py", root, cwd_parent, "db/repository.py"),
        ("/tmp/sample-target/db/repository.py", root, None, "db/repository.py"),
        ("db/repository.py", root, root, "db/repository.py"),
    ]

    for input_path, r, cwd, expected in tests:
        result = normalize_path(input_path, r, cwd)
        status = "OK" if result == expected else "FAILED"
        print(f"[{status}] normalize_path('{input_path}', cwd={cwd}) -> '{result}' (expected: '{expected}')")
