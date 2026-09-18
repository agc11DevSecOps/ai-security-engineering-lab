from sqlalchemy import create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class Record(Base):
    __tablename__ = "records"
    record_id: Mapped[str] = mapped_column(primary_key=True)


def lookup_record(record_id: str):
    engine = create_engine("sqlite:///records.db")
    with Session(engine) as session:
        statement = select(Record).where(Record.record_id == record_id)
        return session.scalars(statement).all()
