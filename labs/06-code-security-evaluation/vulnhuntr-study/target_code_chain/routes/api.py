"""
Endpoint HTTP real: aqui entra el input remoto del atacante.
"""
from fastapi import FastAPI, Query
from services.report_service import generate_user_report

app = FastAPI()


@app.get("/api/reports")
def get_report(user_ref: str = Query(...)):
    """
    Endpoint publico que genera un reporte de usuario.
    El parametro user_ref viene directamente del querystring del atacante.
    """
    return generate_user_report(user_ref)
