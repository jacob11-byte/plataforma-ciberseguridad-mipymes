from __future__ import annotations

import json
import subprocess
from typing import Any


def run_powershell(script: str, timeout: int = 45) -> Any:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        return {"error": completed.stderr.strip()}
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output
