"""
SQLite storage - keeps every analysis run so results survive a server restart.
Uses parameterized queries only (safe against SQL injection).
"""
import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS runs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            filename TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            result_json TEXT NOT NULL)""")


def save_run(filename, result):
    with _connect() as conn:
        cur = conn.execute("INSERT INTO runs (filename, created_at, result_json) VALUES (?, ?, ?)",
                           (filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), json.dumps(result)))
        return cur.lastrowid


def get_latest_run():
    with _connect() as conn:
        row = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    result = json.loads(row["result_json"])
    result["run_id"], result["created_at"] = row["id"], row["created_at"]
    return result


def list_runs(limit=5):
    with _connect() as conn:
        rows = conn.execute("SELECT id, filename, created_at FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
