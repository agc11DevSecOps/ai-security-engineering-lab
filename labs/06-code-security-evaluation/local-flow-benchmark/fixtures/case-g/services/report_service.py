from db.repository import lookup_record


def build_report(record_id: str) -> dict:
    canonical_id = str(int(record_id, 10))
    rows = lookup_record(canonical_id)
    return {"records": rows}
