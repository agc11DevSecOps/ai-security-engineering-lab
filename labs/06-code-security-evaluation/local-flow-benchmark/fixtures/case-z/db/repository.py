import requests


SERVICES = {"catalog": "https://catalog.example.test/report"}


def fetch_report(record_id: str):
    return requests.get(SERVICES[record_id], timeout=2)
