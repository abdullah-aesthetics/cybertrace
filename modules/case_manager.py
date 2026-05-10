"""
Case Management Module
Handles case status, investigator notes, evidence attachments,
and false positive marking — like a real SOC ticketing system.
"""
import sqlite3
import json
import os
from datetime import datetime

DB_PATH = "database/cybertrace.db"

VALID_STATUSES = ["Open", "In Progress", "Closed", "False Positive", "Escalated"]


def init_case_management():
    """Add case management tables to existing DB."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Case notes table
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            author TEXT,
            note TEXT,
            timestamp TEXT,
            note_type TEXT DEFAULT 'general'
        )
    """)

    # Case status table
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_status (
            case_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'Open',
            priority TEXT DEFAULT 'Medium',
            assigned_to TEXT,
            updated_at TEXT,
            closed_at TEXT,
            false_positive INTEGER DEFAULT 0,
            false_positive_reason TEXT
        )
    """)

    # Evidence table
    c.execute("""
        CREATE TABLE IF NOT EXISTS case_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            filename TEXT,
            filepath TEXT,
            file_type TEXT,
            description TEXT,
            uploaded_by TEXT,
            uploaded_at TEXT
        )
    """)

    conn.commit()
    conn.close()


# ── Status management ─────────────────────────────────────────────────────────

def get_case_status(case_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM case_status WHERE case_id=?", (case_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "case_id": case_id, "status": "Open",
        "priority": "Medium", "assigned_to": None,
        "updated_at": None, "closed_at": None,
        "false_positive": 0, "false_positive_reason": None
    }


def update_case_status(case_id, status, assigned_to=None, priority=None):
    if status not in VALID_STATUSES:
        return {"error": f"Invalid status. Must be one of: {VALID_STATUSES}"}

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    closed_at = now if status == "Closed" else None

    c.execute("""
        INSERT INTO case_status (case_id, status, priority, assigned_to, updated_at, closed_at)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(case_id) DO UPDATE SET
            status=excluded.status,
            priority=COALESCE(excluded.priority, priority),
            assigned_to=COALESCE(excluded.assigned_to, assigned_to),
            updated_at=excluded.updated_at,
            closed_at=COALESCE(excluded.closed_at, closed_at)
    """, (case_id, status, priority or "Medium", assigned_to, now, closed_at))
    conn.commit()
    conn.close()
    return {"success": True, "case_id": case_id, "status": status}


def mark_false_positive(case_id, reason, author):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        INSERT INTO case_status (case_id, status, false_positive, false_positive_reason, updated_at)
        VALUES (?,?,?,?,?)
        ON CONFLICT(case_id) DO UPDATE SET
            status='False Positive',
            false_positive=1,
            false_positive_reason=excluded.false_positive_reason,
            updated_at=excluded.updated_at
    """, (case_id, "False Positive", 1, reason, now))
    conn.commit()
    conn.close()

    # Add an automatic note
    add_note(case_id, author, f"Marked as false positive: {reason}", "false_positive")
    return {"success": True, "case_id": case_id}


# ── Notes ─────────────────────────────────────────────────────────────────────

def add_note(case_id, author, note, note_type="general"):
    if not note.strip():
        return {"error": "Note cannot be empty"}

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        INSERT INTO case_notes (case_id, author, note, timestamp, note_type)
        VALUES (?,?,?,?,?)
    """, (case_id, author or "System", note, now, note_type))
    note_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"success": True, "note_id": note_id, "timestamp": now}


def get_notes(case_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY timestamp DESC", (case_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_note(note_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM case_notes WHERE id=?", (note_id,))
    conn.commit()
    conn.close()
    return {"success": True}


# ── Evidence ──────────────────────────────────────────────────────────────────

def attach_evidence(case_id, filename, filepath, file_type, description, uploaded_by):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        INSERT INTO case_evidence
        (case_id, filename, filepath, file_type, description, uploaded_by, uploaded_at)
        VALUES (?,?,?,?,?,?,?)
    """, (case_id, filename, filepath, file_type, description, uploaded_by, now))
    ev_id = c.lastrowid
    conn.commit()
    conn.close()
    return {"success": True, "evidence_id": ev_id, "timestamp": now}


def get_evidence(case_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM case_evidence WHERE case_id=? ORDER BY uploaded_at DESC", (case_id,))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_case_management_stats():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    stats = {"by_status": {}, "by_priority": {}, "false_positives": 0, "unassigned": 0}

    try:
        c.execute("SELECT status, COUNT(*) as cnt FROM case_status GROUP BY status")
        for row in c.fetchall():
            stats["by_status"][row["status"]] = row["cnt"]

        c.execute("SELECT priority, COUNT(*) as cnt FROM case_status GROUP BY priority")
        for row in c.fetchall():
            stats["by_priority"][row["priority"]] = row["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM case_status WHERE false_positive=1")
        stats["false_positives"] = c.fetchone()["cnt"]

        c.execute("SELECT COUNT(*) as cnt FROM case_status WHERE assigned_to IS NULL OR assigned_to=''")
        stats["unassigned"] = c.fetchone()["cnt"]
    except Exception:
        pass

    conn.close()
    return stats
