from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


ALLOWED_SECURITY_EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4720, 4726, 4732, 4733, 4740]


def collect_security_events(hours: int = 24, limit: int = 100) -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    ids = ",".join(str(item) for item in ALLOWED_SECURITY_EVENT_IDS)
    data = run_powershell(
        "$start=(Get-Date).AddHours(-" + str(int(hours)) + "); "
        "$ids=@(" + ids + "); "
        "Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=$ids} -ErrorAction SilentlyContinue | "
        f"Select-Object -First {int(limit)} TimeCreated,Id,ProviderName,LevelDisplayName,MachineName | ConvertTo-Json -Compress",
        timeout=60,
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) and not data.get("error") else [])
    return [
        {
            "time_created": row.get("TimeCreated"),
            "event_id": row.get("Id"),
            "provider": row.get("ProviderName"),
            "level": row.get("LevelDisplayName"),
            "machine": row.get("MachineName"),
        }
        for row in rows
        if isinstance(row, dict)
    ]
