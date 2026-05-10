import sqlite3
import json
from datetime import datetime

DB_PATH = "database/cybertrace.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT UNIQUE,
            target TEXT,
            target_type TEXT,
            investigator TEXT,
            timestamp TEXT,
            risk_score INTEGER,
            threat_level TEXT,
            osint_data TEXT,
            packet_data TEXT,
            malware_data TEXT,
            recommendations TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER,
            timestamp TEXT,
            flags TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_investigation(data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR REPLACE INTO investigations
            (case_id, target, target_type, investigator, timestamp, risk_score,
             threat_level, osint_data, packet_data, malware_data, recommendations)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data["case_id"], data["target"], data["target_type"],
            data["investigator"], data["timestamp"], data["risk_score"],
            data["threat_level"], json.dumps(data.get("osint_data", {})),
            json.dumps(data.get("packet_data", {})),
            json.dumps(data.get("malware_data", {})),
            json.dumps(data.get("recommendations", []))
        ))
        conn.commit()
    finally:
        conn.close()

def save_packet_log(case_id, packet):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO packet_logs
            (case_id, src_ip, dst_ip, protocol, src_port, dst_port, length, timestamp, flags)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            case_id, packet.get("src_ip"), packet.get("dst_ip"),
            packet.get("protocol"), packet.get("src_port"),
            packet.get("dst_port"), packet.get("length"),
            packet.get("timestamp"), packet.get("flags")
        ))
        conn.commit()
    finally:
        conn.close()

def get_all_investigations():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM investigations ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_investigation(case_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM investigations WHERE case_id=?", (case_id,))
    row = c.fetchone()
    conn.close()
    if row:
        d = dict(row)
        for f in ["osint_data", "packet_data", "malware_data", "recommendations"]:
            try:
                d[f] = json.loads(d[f]) if d[f] else {}
            except Exception:
                d[f] = {}
        return d
    return None

def get_packet_logs(case_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM packet_logs WHERE case_id=? ORDER BY timestamp DESC LIMIT 100", (case_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]
