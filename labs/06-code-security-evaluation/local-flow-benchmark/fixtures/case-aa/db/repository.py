import requests


def submit_report(record_id: str):
    return requests.post(record_id, timeout=2)
