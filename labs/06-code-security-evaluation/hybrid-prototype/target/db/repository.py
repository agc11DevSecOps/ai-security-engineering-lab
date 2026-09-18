"""
Capa de acceso a datos: aqui esta el sink real (SQL injection), pero
el parametro llego desde 2 capas antes (endpoint -> servicio -> aqui),
nunca sanitizado en el camino.
"""
import sqlite3


def fetch_user_data(ref: str):
    """
    Vulnerable: concatena 'ref' directamente en la query SQL. El valor
    de 'ref' proviene, sin ninguna validacion intermedia, del parametro
    user_ref del endpoint HTTP publico /api/reports.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE reference = '" + ref + "'"
    cursor.execute(query)
    return cursor.fetchall()
