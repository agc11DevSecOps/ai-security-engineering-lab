from db.repository import submit_report


def build_report(record_id: str):
    return submit_report(record_id)
