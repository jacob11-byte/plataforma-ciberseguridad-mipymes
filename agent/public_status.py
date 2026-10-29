from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.outbox import default_data_root


PUBLIC_STATUS_FIELDS = {
    "agent_version",
    "connectivity",
    "dashboard_url",
    "device_name",
    "last_attempt",
    "last_error",
    "last_success",
    "outbox_dead",
    "outbox_pending",
    "service_state",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def public_status_path(data_root: Path | None = None) -> Path:
    return (data_root or default_data_root()) / "public" / "status.json"


def sanitize_status(status: dict[str, Any]) -> dict[str, Any]:
    return {key: status.get(key) for key in sorted(PUBLIC_STATUS_FIELDS) if key in status}


def write_public_status(status: dict[str, Any], data_root: Path | None = None) -> Path:
    path = public_status_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = sanitize_status(status)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix="status-", suffix=".tmp", delete=False
        ) as handle:
            json.dump(clean, handle, ensure_ascii=False, indent=2)
            temporary = Path(handle.name)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def read_public_status(data_root: Path | None = None) -> dict[str, Any]:
    path = public_status_path(data_root)
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {"service_state": "unknown", "connectivity": "unknown"}
    return sanitize_status(value) if isinstance(value, dict) else {}
