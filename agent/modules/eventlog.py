from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


ALLOWED_SECURITY_EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4720, 4726, 4732, 4733, 4740]

# Events that tell a story on their own, with the fields that name who/what.
# Indexes follow the event schemas documented by Microsoft for each ID.
DETECTION_QUERY = r"""
$start = (Get-Date).AddHours(-%(hours)d)
$out = New-Object System.Collections.ArrayList
function Add-Row($e, $fields) {
  $p = $e.Properties
  $row = [ordered]@{ event_id = $e.Id; time_created = $e.TimeCreated.ToString('o') }
  foreach ($k in $fields.Keys) { $i = $fields[$k]; if ($p.Count -gt $i) { $row[$k] = [string]$p[$i].Value } }
  [void]$out.Add([pscustomobject]$row)
}
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=4625} -MaxEvents 500 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ target_user = 5; sub_status = 9; logon_type = 10; workstation = 13; source_ip = 19 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=4720,4726} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ target_user = 0; subject_user = 4 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=4732} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ member_sid = 1; group = 2; group_sid = 4; subject_user = 6 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=4740} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ target_user = 0; caller_computer = 1 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=1102} -MaxEvents 10 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ subject_user = 1 }) }
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row $_ ([ordered]@{ service_name = 0; image_path = 1; start_type = 3; account = 4 }) }
@($out) | ConvertTo-Json -Compress
"""


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


def collect_security_detections(hours: int = 24) -> list[dict[str, Any]] | dict[str, str]:
    """Security-relevant events with the account, IP or binary involved."""
    if os.name != "nt":
        return []
    data = run_powershell(DETECTION_QUERY % {"hours": int(hours)}, timeout=90)
    if isinstance(data, dict) and data.get("error"):
        return {"error": str(data["error"])[:300]}
    if data is None:
        return []
    rows = data if isinstance(data, list) else [data]
    return [row for row in rows if isinstance(row, dict)]
