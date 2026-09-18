from db.repository import parse_value


def build_report(record_id: str):
    return parse_value(record_id)
