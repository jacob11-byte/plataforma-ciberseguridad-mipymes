from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


def collect_installed_software(limit: int = 250) -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "$paths=@("
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        "); "
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation | "
        f"Sort-Object DisplayName -Unique | Select-Object -First {int(limit)} | ConvertTo-Json -Compress"
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) and not data.get("error") else [])
    return [
        {
            "name": row.get("DisplayName"),
            "version": row.get("DisplayVersion"),
            "publisher": row.get("Publisher"),
            "install_date": row.get("InstallDate"),
            "install_location": row.get("InstallLocation"),
        }
        for row in rows
        if isinstance(row, dict)
    ]
