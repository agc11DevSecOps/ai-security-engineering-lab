import subprocess


def lookup_record(record_id: str):
    command = "printf " + record_id
    return subprocess.run(command, shell=True, capture_output=True, text=True)
