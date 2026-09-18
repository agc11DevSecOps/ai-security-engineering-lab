import subprocess


def lookup_record(record_id: str):
    # SAFE: Subprocess called with argument list, no shell
    return subprocess.run(["printf", record_id], capture_output=True, text=True, check=True)