from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("data/cybercheck.db")


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                company_id INTEGER NOT NULL REFERENCES companies(id),
                name TEXT NOT NULL,
                os_version TEXT,
                architecture TEXT,
                ip_address TEXT,
                token TEXT NOT NULL UNIQUE,
                last_seen TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS evidences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                control TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                rule_id TEXT NOT NULL,
                control TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                closure_criteria TEXT NOT NULL,
                first_scan_id INTEGER,
                last_scan_id INTEGER,
                resolved_scan_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(device_id, rule_id)
            );
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL REFERENCES findings(id),
                previous_status TEXT,
                new_status TEXT NOT NULL,
                note TEXT NOT NULL,
                scan_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL REFERENCES devices(device_id),
                task_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                parameters_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                delivered_at TEXT,
                completed_at TEXT
            );
            """
        )
        company = db.execute("SELECT id FROM companies WHERE name = ?", ("MIPYME Demo",)).fetchone()
        if not company:
            cur = db.execute("INSERT INTO companies(name) VALUES (?)", ("MIPYME Demo",))
            company_id = cur.lastrowid
        else:
            company_id = company["id"]
        db.execute(
            """
            INSERT OR IGNORE INTO devices(device_id, company_id, name, os_version, architecture, token)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("PC-CONTABILIDAD-001", company_id, "PC Contabilidad Demo", "Windows 11 Demo", "x64", "demo-token"),
        )


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def generate_token() -> str:
    return secrets.token_urlsafe(32)
