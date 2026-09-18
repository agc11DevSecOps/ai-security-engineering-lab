from db.repository import lookup_record


def build_report(record_id: str):
    return lookup_record(record_id)