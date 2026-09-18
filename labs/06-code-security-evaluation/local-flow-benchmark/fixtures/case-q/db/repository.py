from pathlib import Path


def lookup_record(record_id: str):
    path = Path("/srv/reports") / record_id
    return path.read_text(encoding="utf-8")
