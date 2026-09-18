from fastapi import Query

from services.report_service import build_report


def get_report(record_id: str = Query(...)):
    return build_report(record_id)
