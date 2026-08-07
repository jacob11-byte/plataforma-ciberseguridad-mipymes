from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Iterable

DB_PATH = Path("data/cybercheck.db")

SQLITE_SCHEMA = """
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

POSTGRES_SCHEMA = (
    SQLITE_SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    .replace("created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP", "created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP")
    .replace("updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP", "updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP")
    .replace("last_seen TEXT", "last_seen TIMESTAMPTZ")
    .replace("delivered_at TEXT", "delivered_at TIMESTAMPTZ")
    .replace("completed_at TEXT", "completed_at TIMESTAMPTZ")
)


class Database:
    def __init__(self) -> None:
        self.database_url = os.getenv("DATABASE_URL")
        self.is_postgres = bool(self.database_url)
        if self.is_postgres:
            import psycopg
            from psycopg.rows import dict_row

            self.conn = psycopg.connect(self.database_url, row_factory=dict_row)
        else:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(DB_PATH)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

    def _sql(self, sql: str) -> str:
        if self.is_postgres:
            return sql.replace("?", "%s")
        return sql

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        cursor = self.conn.cursor()
        cursor.execute(self._sql(sql), tuple(params))
        return Cursor(cursor, self.is_postgres)

    def executescript(self, script: str) -> None:
        if self.is_postgres:
            with self.conn.cursor() as cursor:
                cursor.execute(script)
        else:
            self.conn.executescript(script)


class Cursor:
    def __init__(self, cursor: Any, is_postgres: bool) -> None:
        self.cursor = cursor
        self.is_postgres = is_postgres

    @property
    def lastrowid(self) -> int | None:
        if self.is_postgres:
            row = self.cursor.fetchone()
            return row["id"] if row else None
        return self.cursor.lastrowid

    def fetchone(self) -> Any:
        return self.cursor.fetchone()

    def fetchall(self) -> list[Any]:
        return self.cursor.fetchall()

    def __iter__(self) -> Any:
        return iter(self.cursor)


def connect() -> Database:
    return Database()


def init_db() -> None:
    with connect() as db:
        db.executescript(POSTGRES_SCHEMA if db.is_postgres else SQLITE_SCHEMA)
        company = db.execute("SELECT id FROM companies WHERE name = ?", ("MIPYME Demo",)).fetchone()
        if not company:
            company_id = insert_returning_id(db, "INSERT INTO companies(name) VALUES (?)", ("MIPYME Demo",))
        else:
            company_id = company["id"]
        db.execute(
            """
            INSERT INTO devices(device_id, company_id, name, os_version, architecture, token)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO NOTHING
            """,
            ("PC-CONTABILIDAD-001", company_id, "PC Contabilidad Demo", "Windows 11 Demo", "x64", "demo-token"),
        )


def insert_returning_id(db: Database, sql: str, params: Iterable[Any]) -> int:
    if db.is_postgres:
        return int(db.execute(f"{sql} RETURNING id", params).lastrowid)
    return int(db.execute(sql, params).lastrowid)


def row_to_dict(row: Any | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def generate_token() -> str:
    return secrets.token_urlsafe(32)
