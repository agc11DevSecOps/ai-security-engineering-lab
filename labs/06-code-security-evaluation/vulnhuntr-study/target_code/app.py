"""
Código de prueba con vulnerabilidades intencionadas y variadas,
para generar hallazgos reales con Bandit y tener material de triage.
NUNCA se ejecuta este código -- solo se analiza estáticamente.
"""
import subprocess
import hashlib
import pickle
import sqlite3


# --- CRITICAL: hardcoded credentials ---
DB_PASSWORD = "DEMO_ONLY_NOT_A_SECRET"
API_KEY = "DEMO_ONLY_NOT_A_TOKEN"


def run_diagnostic(hostname):
    # --- HIGH: shell injection vía subprocess con shell=True ---
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # --- HIGH: SQL injection, concatenación directa de input ---
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password):
    # --- MEDIUM: uso de MD5 para hashing de contraseñas (débil, no salted) ---
    return hashlib.md5(password.encode()).hexdigest()


def load_config(path):
    # --- MEDIUM/HIGH: deserialización insegura, mismo patrón que Fase 1 ---
    with open(path, "rb") as f:
        return pickle.load(f)


def eval_user_expression(expr):
    # --- CRITICAL: eval sobre input de usuario ---
    return eval(expr)


def debug_endpoint():
    # --- LOW: uso de assert para control de flujo (se elimina con -O) ---
    assert True, "esto no debería estar en producción"
