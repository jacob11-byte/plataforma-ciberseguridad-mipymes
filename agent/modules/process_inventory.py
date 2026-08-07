from __future__ import annotations

import os
from typing import Any

from agent.core.powershell import run_powershell


def collect_processes(limit: int = 200) -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "$items = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        f"Select-Object -First {int(limit)} ProcessId,Name,ExecutablePath,ParentProcessId,CreationDate; "
        "$items | ForEach-Object { "
        "$sigStatus=$null; $signer=$null; "
        "if ($_.ExecutablePath) { "
        "$sig=Get-AuthenticodeSignature -FilePath $_.ExecutablePath -ErrorAction SilentlyContinue; "
        "$sigStatus=[string]$sig.Status; $signer=$sig.SignerCertificate.Subject "
        "} "
        "[pscustomobject]@{ ProcessId=$_.ProcessId; Name=$_.Name; ExecutablePath=$_.ExecutablePath; "
        "ParentProcessId=$_.ParentProcessId; CreationDate=$_.CreationDate; SignatureStatus=$sigStatus; Signer=$signer } "
        "} | ConvertTo-Json -Compress",
        timeout=90,
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) and not data.get("error") else [])
    return [
        {
            "process_id": row.get("ProcessId"),
            "name": row.get("Name"),
            "executable_path": row.get("ExecutablePath"),
            "parent_process_id": row.get("ParentProcessId"),
            "creation_date": row.get("CreationDate"),
            "signature_status": row.get("SignatureStatus"),
            "signer": row.get("Signer"),
        }
        for row in rows
        if isinstance(row, dict)
    ]
