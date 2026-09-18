from sqlalchemy import create_engine, text


def lookup_record(record_id: str):
    engine = create_engine("sqlite:///records.db")
    with engine.connect() as connection:
        statement = text(f"SELECT * FROM records WHERE record_id = '{record_id}'")
        result = connection.execute(statement)
        return result.fetchall()
