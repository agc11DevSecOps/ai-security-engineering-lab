"""
Capa de servicio: recibe el input ya "procesado" por el endpoint y lo
pasa a la capa de acceso a datos, sin ninguna validacion real.
"""
from db.repository import fetch_user_data


def generate_user_report(user_ref: str) -> dict:
    """
    Prepara un reporte a partir de la referencia de usuario.
    NO sanitiza user_ref -- simplemente lo reenvia a la capa de datos.
    """
    normalized_ref = user_ref.strip()
    data = fetch_user_data(normalized_ref)
    return {"report": data}
