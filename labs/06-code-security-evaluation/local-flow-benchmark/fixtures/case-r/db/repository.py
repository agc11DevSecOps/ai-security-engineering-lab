from pathlib import Path


def lookup_record(record_id: str):
    name = Path(record_id).name
    path = Path("/srv/reports") / name
    return path.read_text(encoding="utf-8")
