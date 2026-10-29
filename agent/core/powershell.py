from __future__ import annotations

import json
import os
import subprocess
from typing import Any

# Windows PowerShell writes with the OEM code page by default, which mangles
# accented names ("tactil" -> "tÂ ctil") on Spanish systems. Force UTF-8.
UTF8_PREAMBLE = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $OutputEncoding = [System.Text.Encoding]::UTF8; "


def run_powershell(script: str, timeout: int = 45) -> Any:
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", UTF8_PREAMBLE + script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            **options,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"PowerShell no disponible: {type(exc).__name__}"}
    if completed.returncode != 0:
        return {"error": completed.stderr.strip() or f"PowerShell termino con codigo {completed.returncode}"}
    output = completed.stdout.strip().lstrip("﻿")
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output
