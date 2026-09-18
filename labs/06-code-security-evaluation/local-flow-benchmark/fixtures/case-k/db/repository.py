import sqlite3


def lookup_record(record_id: str):
    connection = sqlite3.connect("records.db")
    cursor = connection.cursor()
    # VULNERABLE: String concatenation in SQL query
    statement = "SELECT * FROM records WHERE name = '" + record_id + "'"
    cursor.execute(statement)
    return cursor.fetchall()