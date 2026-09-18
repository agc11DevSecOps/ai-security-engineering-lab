import requests


def fetch_report(record_id: str):
    return requests.get(record_id, timeout=2)
