import sqlite3


def lookup_record(record_id: str):
    connection = sqlite3.connect("records.db")
    cursor = connection.cursor()
    statement = "SELECT * FROM records WHERE record_id = '" + record_id + "'"
    cursor.execute(statement)
    return cursor.fetchall()
