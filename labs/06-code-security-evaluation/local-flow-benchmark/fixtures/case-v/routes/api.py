import html

from fastapi import Query
from fastapi.responses import HTMLResponse


def get_report(record_id: str = Query(...)):
    return HTMLResponse(f"<h1>{html.escape(record_id)}</h1>")
