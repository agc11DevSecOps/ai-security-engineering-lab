"""Intentionally vulnerable static-analysis fixture for advisory triage.

Never execute, import, deploy, or reuse this file. The values below are clearly
synthetic placeholders and not credentials.
"""
import subprocess
import hashlib
import pickle
import sqlite3


# --- CRITICAL: hardcoded placeholder values, intentionally flagged by Bandit ---
DB_PASSWORD = "SYNTHETIC_DEMO_ONLY_NOT_A_SECRET"
API_KEY = "SYNTHETIC_DEMO_API_KEY_NOT_A_SECRET"


def run_diagnostic(hostname):
    # --- HIGH: shell injection through subprocess with shell=True ---
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    return result.stdout


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # --- HIGH: SQL injection through direct input concatenation ---
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password):
    # --- MEDIUM: MD5 password hashing is weak and unsalted ---
    return hashlib.md5(password.encode()).hexdigest()


def load_config(path):
    # --- MEDIUM/HIGH: unsafe deserialization ---
    with open(path, "rb") as f:
        return pickle.load(f)


def eval_user_expression(expr):
    # --- CRITICAL: eval on user-controlled input ---
    return eval(expr)


def debug_endpoint():
    # --- LOW: assert for control flow is removed with -O ---
    assert True, "this assertion should not appear in production"
