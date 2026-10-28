from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def run_powershell(script: str, timeout: int = 45) -> Any:
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            **options,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"PowerShell no disponible: {type(exc).__name__}"}
    if completed.returncode != 0:
        return {"error": completed.stderr.strip() or f"PowerShell termino con codigo {completed.returncode}"}
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output
