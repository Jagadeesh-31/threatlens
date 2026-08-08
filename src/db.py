"""
db.py — SQLite storage layer for ThreatLens.

Handles creating the alerts table, inserting new alerts
(with de-duplication), and querying alerts for the dashboard.
"""

import sqlite3
import math
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "threatlens.db"


def get_connection() -> sqlite3.Connection:
    """Return a connection to the ThreatLens SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the alerts table if it doesn't already exist."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            user TEXT,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(timestamp, src_ip, technique_id, description)
        )
    """)
    conn.commit()
    conn.close()
    print(f"[+] Database ready at {DB_PATH}")


def insert_alerts(alerts: list[dict]) -> int:
    """
    Insert a list of alert dicts into the database.
    Uses INSERT OR IGNORE to skip duplicates (same timestamp/ip/technique/description).
    Returns the number of NEW alerts actually inserted.
    """
    if not alerts:
        return 0

    conn = get_connection()
    cur = conn.cursor()
    inserted = 0

    for alert in alerts:
        ts = alert["timestamp"]
        ts_str = ts.isoformat() if isinstance(ts, datetime) else str(ts)
        src_ip = alert.get("src_ip")
        if src_ip is None or (isinstance(src_ip, float) and math.isnan(src_ip)) or str(src_ip).lower() == "nan":
            src_ip = "local"

        cur.execute("""
            INSERT OR IGNORE INTO alerts
                (timestamp, src_ip, user, technique_id, technique_name, severity, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts_str,
            src_ip,
            alert.get("user"),
            alert["technique_id"],
            alert["technique_name"],
            alert["severity"],
            alert["description"],
            datetime.now().isoformat(),
        ))
        if cur.rowcount > 0:
            inserted += 1

    conn.commit()
    conn.close()
    return inserted


def query_alerts(severity: str = None, technique_id: str = None,
                  src_ip: str = None, limit: int = 500) -> list[dict]:
    """
    Query alerts with optional filters. Returns most recent first.
    """
    conn = get_connection()
    cur = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if technique_id:
        query += " AND technique_id = ?"
        params.append(technique_id)
    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cur.execute(query, params)
    rows = [dict(row) for row in cur.fetchall()]
    conn.close()
    return rows


def get_summary_stats() -> dict:
    """Return quick summary counts for the dashboard header."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as total FROM alerts")
    total = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) as high FROM alerts WHERE severity = 'High'")
    high = cur.fetchone()["high"]

    cur.execute("SELECT COUNT(DISTINCT src_ip) as ips FROM alerts")
    unique_ips = cur.fetchone()["ips"]

    conn.close()
    return {"total_alerts": total, "high_severity": high, "unique_ips": unique_ips}


def clear_all_alerts() -> None:
    """Wipe the alerts table — useful when re-running demos from scratch."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    print("[+] All alerts cleared.")


if __name__ == "__main__":
    init_db()
    stats = get_summary_stats()
    print(f"[+] Current DB stats: {stats}")
