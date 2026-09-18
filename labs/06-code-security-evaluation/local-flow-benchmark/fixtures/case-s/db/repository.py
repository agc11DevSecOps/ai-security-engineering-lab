import pickle


def lookup_record(record_id: str):
    payload = record_id.encode("utf-8")
    return pickle.loads(payload)
