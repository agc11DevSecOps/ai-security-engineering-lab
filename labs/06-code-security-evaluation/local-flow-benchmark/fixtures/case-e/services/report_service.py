from db.repository import lookup_record


def build_report(record_id: str) -> dict:
    normalized_id = record_id.strip()
    rows = lookup_record(normalized_id)
    return {"records": rows}
