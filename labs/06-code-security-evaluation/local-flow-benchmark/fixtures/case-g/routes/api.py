from fastapi import FastAPI, Query

from services.report_service import build_report

app = FastAPI()


@app.get("/records")
def get_record(record_id: str = Query(...)):
    return build_report(record_id)
