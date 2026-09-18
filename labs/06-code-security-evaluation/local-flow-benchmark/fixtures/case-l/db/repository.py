import sqlite3


def lookup_record(record_id: str):
    connection = sqlite3.connect("records.db")
    cursor = connection.cursor()
    # SAFE: Parametrized query using named placeholder
    cursor.execute("SELECT * FROM records WHERE name = ?", (record_id,))
    return cursor.fetchall()