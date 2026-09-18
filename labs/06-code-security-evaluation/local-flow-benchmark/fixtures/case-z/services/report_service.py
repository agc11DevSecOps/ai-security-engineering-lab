from db.repository import fetch_report


def build_report(record_id: str):
    return fetch_report(record_id)
