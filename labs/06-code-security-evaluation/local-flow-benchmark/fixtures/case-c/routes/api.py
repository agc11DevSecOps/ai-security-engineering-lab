from fastapi import FastAPI, Request

from services.report_service import build_report

app = FastAPI()


@app.get("/records")
def get_record(request: Request):
    record_id = request.query_params["record_id"]
    return build_report(record_id)
