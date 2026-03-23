"""SQLite database connection management and schema initialization."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from app.config import DB_PATH, REPORT_EXPIRY_DAYS


def get_db() -> sqlite3.Connection:
    """Return a new SQLite connection with row factory enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create tables if they do not exist."""
    conn = get_db()
    try:
        # Create base tables
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id              TEXT PRIMARY KEY,
                github_url      TEXT NOT NULL,
                commit_sha      TEXT DEFAULT '',
                skill_name      TEXT DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'pending',
                risk_score      INTEGER DEFAULT 0,
                risk_level      TEXT DEFAULT '',
                report_json     TEXT DEFAULT '',
                error_message   TEXT DEFAULT '',
                parent_scan_id  TEXT,
                is_multi_skill  INTEGER DEFAULT 0,
                created_at      TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                FOREIGN KEY (parent_scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                dimension       TEXT NOT NULL,
                severity        TEXT NOT NULL,
                file_path       TEXT DEFAULT '',
                line_number     INTEGER DEFAULT 0,
                pattern         TEXT DEFAULT '',
                description     TEXT NOT NULL,
                reference       TEXT DEFAULT '',
                remediation_zh  TEXT DEFAULT '',
                remediation_en  TEXT DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
        """)
        conn.commit()

        # Migrate existing databases: add new columns if missing
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "parent_scan_id" not in existing_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN parent_scan_id TEXT")
        if "is_multi_skill" not in existing_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN is_multi_skill INTEGER DEFAULT 0")
        conn.commit()

        # Create index on parent_scan_id (after migration ensures column exists)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_parent ON scans(parent_scan_id)")
        conn.commit()

        # Deep Scan tables
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS deep_scans (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                model TEXT NOT NULL,
                provider TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                risk_score INTEGER,
                total_turns INTEGER DEFAULT 0,
                total_tool_calls INTEGER DEFAULT 0,
                total_tokens_in INTEGER DEFAULT 0,
                total_tokens_out INTEGER DEFAULT 0,
                actual_cost REAL DEFAULT 0,
                report_json TEXT,
                error_message TEXT,
                created_at TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS trace_steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                deep_scan_id TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT,
                timestamp TEXT,
                risk_level TEXT,
                related_finding TEXT,
                FOREIGN KEY(deep_scan_id) REFERENCES deep_scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_deep_scans_scan_id ON deep_scans(scan_id);
            CREATE INDEX IF NOT EXISTS idx_trace_steps_deep_scan_id ON trace_steps(deep_scan_id);
        """)
        conn.commit()
    finally:
        conn.close()


def create_scan(github_url: str) -> str:
    """Insert a new scan record and return its UUID."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=REPORT_EXPIRY_DAYS)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO scans (id, github_url, status, created_at, expires_at) VALUES (?, ?, 'pending', ?, ?)",
            (scan_id, github_url, now.isoformat(), expires.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return scan_id


def update_scan_status(scan_id: str, status: str, **kwargs):
    """Update scan status and optional fields."""
    conn = get_db()
    try:
        sets = ["status = ?"]
        vals = [status]
        for key in ("commit_sha", "skill_name", "risk_score", "risk_level", "report_json", "error_message", "is_multi_skill"):
            if key in kwargs:
                sets.append(f"{key} = ?")
                vals.append(kwargs[key])
        vals.append(scan_id)
        conn.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()
    finally:
        conn.close()


def insert_findings(scan_id: str, findings: list[dict]):
    """Batch-insert findings for a scan."""
    conn = get_db()
    try:
        conn.executemany(
            """INSERT INTO findings
               (scan_id, dimension, severity, file_path, line_number, pattern, description, reference, remediation_zh, remediation_en)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id,
                    f["dimension"],
                    f["severity"],
                    f.get("file_path", ""),
                    f.get("line_number", 0),
                    f.get("pattern", ""),
                    f["description"],
                    f.get("reference", ""),
                    f.get("remediation_zh", ""),
                    f.get("remediation_en", ""),
                )
                for f in findings
            ],
        )
        conn.commit()
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[dict]:
    """Fetch a scan row as a dict."""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_findings(scan_id: str) -> list[dict]:
    """Fetch all findings for a scan."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_scans(limit: int = 20) -> list[dict]:
    """Fetch the most recent scans (excluding child scans)."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, github_url, skill_name, status, risk_score, risk_level, is_multi_skill, created_at FROM scans WHERE parent_scan_id IS NULL ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_child_scan(parent_scan_id: str, github_url: str, skill_name: str) -> str:
    """Insert a child scan row linked to a parent and return its UUID."""
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=REPORT_EXPIRY_DAYS)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO scans (id, github_url, skill_name, status, parent_scan_id, created_at, expires_at) VALUES (?, ?, ?, 'pending', ?, ?, ?)",
            (scan_id, github_url, skill_name, parent_scan_id, now.isoformat(), expires.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return scan_id


def get_child_scans(parent_scan_id: str) -> list[dict]:
    """Fetch all child scans for a parent, ordered by risk_score DESC."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE parent_scan_id = ? ORDER BY risk_score DESC",
            (parent_scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def count_child_status(parent_scan_id: str) -> dict:
    """Return (total, done, error) counts for child scans."""
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) as done,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error
               FROM scans WHERE parent_scan_id = ?""",
            (parent_scan_id,),
        ).fetchone()
        return {"total": row["total"], "done": row["done"], "error": row["error"]}
    finally:
        conn.close()


# ── Deep Scan CRUD ──────────────────────────────────────────────────


def create_deep_scan(deep_scan_id: str, scan_id: str, model: str, provider: str) -> str:
    """Insert a new deep_scan record."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO deep_scans (id, scan_id, model, provider, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (deep_scan_id, scan_id, model, provider, now),
        )
        conn.commit()
    finally:
        conn.close()
    return deep_scan_id


def update_deep_scan(deep_scan_id: str, **kwargs):
    """Update deep_scan fields."""
    conn = get_db()
    try:
        sets = []
        vals = []
        allowed = (
            "status", "risk_score", "total_turns", "total_tool_calls",
            "total_tokens_in", "total_tokens_out", "actual_cost",
            "report_json", "error_message",
        )
        for key in allowed:
            if key in kwargs:
                sets.append(f"{key} = ?")
                vals.append(kwargs[key])
        if not sets:
            return
        vals.append(deep_scan_id)
        conn.execute(f"UPDATE deep_scans SET {', '.join(sets)} WHERE id = ?", vals)
        conn.commit()
    finally:
        conn.close()


def get_deep_scan(deep_scan_id: str) -> Optional[dict]:
    """Fetch a deep_scan row as a dict."""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM deep_scans WHERE id = ?", (deep_scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_deep_scans_for_scan(scan_id: str) -> list[dict]:
    """Fetch all deep scans for a static scan."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM deep_scans WHERE scan_id = ? ORDER BY created_at DESC",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def insert_trace_step(deep_scan_id: str, step_number: int, role: str,
                      content: str, risk_level: Optional[str] = None,
                      related_finding: Optional[str] = None):
    """Insert a single trace step."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO trace_steps
               (deep_scan_id, step_number, role, content, timestamp, risk_level, related_finding)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (deep_scan_id, step_number, role, content, now, risk_level, related_finding),
        )
        conn.commit()
    finally:
        conn.close()


def get_trace_steps(deep_scan_id: str) -> list[dict]:
    """Fetch all trace steps for a deep scan, ordered by step_number."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM trace_steps WHERE deep_scan_id = ? ORDER BY step_number",
            (deep_scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
