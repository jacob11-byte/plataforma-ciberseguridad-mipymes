from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


MAX_PENDING_RESULTS = 1_000
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024


def default_data_root() -> Path:
    configured = os.environ.get("CYBERCHECK_DATA_DIR")
    if configured:
        return Path(configured)
    program_data = os.environ.get("PROGRAMDATA")
    if program_data:
        return Path(program_data) / "CyberCheck"
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "CyberCheck"


@dataclass(frozen=True)
class OutboxItem:
    id: int
    request_id: str
    payload: dict[str, Any]
    attempts: int


class Outbox:
    """Durable, token-free queue for scan results awaiting delivery."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_data_root() / "outbox.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS pending_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_ready
                    ON pending_results(status, next_attempt_at, created_at);
                """
            )

    def enqueue(self, request_id: str, payload: dict[str, Any]) -> bool:
        if not request_id or payload.get("request_id") != request_id:
            raise ValueError("El request_id de la cola no coincide con el resultado")
        if "token" in payload or "registration_code" in payload:
            raise ValueError("La cola nunca debe almacenar credenciales")
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(serialized.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError("El resultado excede el tamano maximo permitido para la cola")
        now = int(time.time())
        with self._connection() as db:
            pending = db.execute(
                "SELECT COUNT(*) FROM pending_results WHERE status='pending'"
            ).fetchone()[0]
            existing = db.execute(
                "SELECT id FROM pending_results WHERE request_id=?", (request_id,)
            ).fetchone()
            if existing:
                return False
            if pending >= MAX_PENDING_RESULTS:
                raise RuntimeError("La cola offline alcanzo su limite de seguridad")
            db.execute(
                """
                INSERT INTO pending_results(
                    request_id, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (request_id, serialized, now, now),
            )
        return True

    def ready(self, limit: int = 20, now: int | None = None) -> Iterator[OutboxItem]:
        current = int(time.time()) if now is None else now
        with self._connection() as db:
            rows = db.execute(
                """
                SELECT id, request_id, payload_json, attempts
                FROM pending_results
                WHERE status='pending' AND next_attempt_at <= ?
                ORDER BY created_at, id
                LIMIT ?
                """,
                (current, max(1, min(limit, 100))),
            ).fetchall()
        for row in rows:
            yield OutboxItem(
                id=int(row["id"]),
                request_id=str(row["request_id"]),
                payload=json.loads(row["payload_json"]),
                attempts=int(row["attempts"]),
            )

    def mark_sent(self, item_id: int) -> None:
        with self._connection() as db:
            db.execute("DELETE FROM pending_results WHERE id=?", (item_id,))

    def mark_retry(self, item_id: int, error: str, attempts: int) -> None:
        delay = min(30 * 60, max(30, 2 ** min(attempts + 4, 10)))
        now = int(time.time())
        with self._connection() as db:
            db.execute(
                """
                UPDATE pending_results
                SET attempts=attempts+1, next_attempt_at=?, last_error=?, updated_at=?
                WHERE id=? AND status='pending'
                """,
                (now + delay, error[:500], now, item_id),
            )

    def mark_dead(self, item_id: int, error: str) -> None:
        now = int(time.time())
        with self._connection() as db:
            db.execute(
                """
                UPDATE pending_results
                SET status='dead', attempts=attempts+1, last_error=?, updated_at=?
                WHERE id=?
                """,
                (error[:500], now, item_id),
            )

    def stats(self) -> dict[str, int]:
        result = {"pending": 0, "dead": 0}
        with self._connection() as db:
            rows = db.execute(
                "SELECT status, COUNT(*) AS total FROM pending_results GROUP BY status"
            ).fetchall()
        for row in rows:
            if row["status"] in result:
                result[str(row["status"])] = int(row["total"])
        return result
