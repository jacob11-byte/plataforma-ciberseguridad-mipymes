from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ALLOWED_TASKS = {
    "FULL_SCAN",
    "VERIFY_FIREWALL",
    "VERIFY_PORTS",
    "VERIFY_SERVICES",
    "VERIFY_ADMINISTRATORS",
    "VERIFY_UPDATES",
    "VERIFY_ANTIVIRUS",
    "VERIFY_BACKUP",
}


def run_powershell(script: str) -> Any:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=45,
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


def system_info() -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "os_version": platform.platform(),
        "architecture": platform.machine(),
    }


def collect_firewall() -> dict[str, Any]:
    if os.name != "nt":
        return {"domain": True, "private": True, "public": True, "note": "Simulado fuera de Windows"}
    data = run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )
    profiles = data if isinstance(data, list) else [data]
    result = {}
    for profile in profiles:
        if isinstance(profile, dict):
            result[str(profile.get("Name", "")).lower()] = bool(profile.get("Enabled"))
    return {"domain": result.get("domain"), "private": result.get("private"), "public": result.get("public")}


def collect_ports() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    return [
        {"address": row.get("LocalAddress"), "port": row.get("LocalPort"), "process_id": row.get("OwningProcess")}
        for row in rows
    ]


def collect_services(names: list[str]) -> list[dict[str, Any]]:
    if os.name != "nt":
        return [{"name": name, "running": False, "status": "Unavailable"} for name in names]
    quoted = ",".join(f"'{name}'" for name in names)
    data = run_powershell(
        f"Get-Service -Name {quoted} -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType | ConvertTo-Json -Compress"
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    return [
        {"name": row.get("Name"), "status": str(row.get("Status")), "start_type": str(row.get("StartType")), "running": str(row.get("Status")) == "Running"}
        for row in rows
    ]


def collect_admins() -> list[str]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "Get-LocalGroupMember -Group 'Administradores' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
    )
    if isinstance(data, list):
        return [str(item) for item in data]
    return [str(data)] if data else []


def collect_updates() -> dict[str, Any]:
    if os.name != "nt":
        return {"pending_count": 0, "reboot_pending": False}
    reboot = run_powershell(
        "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired' | ConvertTo-Json"
    )
    pending = run_powershell(
        "$s=New-Object -ComObject Microsoft.Update.Session; "
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\"); "
        "$r.Updates.Count | ConvertTo-Json"
    )
    return {"pending_count": int(pending) if str(pending).isdigit() else 0, "reboot_pending": bool(reboot)}


def collect_antivirus() -> dict[str, Any]:
    if os.name != "nt":
        return {"enabled": True, "real_time": True, "name": "Simulado"}
    data = run_powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object -First 1 displayName,productState | ConvertTo-Json -Compress"
    )
    if not isinstance(data, dict):
        return {"enabled": False, "real_time": False, "error": data}
    state = int(data.get("productState") or 0)
    return {"enabled": state != 0, "real_time": state != 0, "name": data.get("displayName"), "product_state": state}


def collect_backup(path: str) -> dict[str, Any]:
    root = Path(path)
    if not root.exists():
        return {"exists": False, "path": path}
    files = [p for p in root.rglob("*") if p.is_file()]
    if not files:
        return {"exists": False, "path": path}
    latest = max(files, key=lambda p: p.stat().st_mtime)
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(latest.stat().st_mtime, timezone.utc)
    return {"exists": True, "path": path, "days_since_last_backup": age.days, "latest_size": latest.stat().st_size}


def collect_evidence(config: dict[str, Any], task_type: str) -> dict[str, Any]:
    evidence: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat(), "system_info": system_info()}
    if task_type in {"FULL_SCAN", "VERIFY_FIREWALL"}:
        evidence["firewall"] = collect_firewall()
    if task_type in {"FULL_SCAN", "VERIFY_PORTS"}:
        evidence["listening_ports"] = collect_ports()
    if task_type in {"FULL_SCAN", "VERIFY_SERVICES"}:
        evidence["services"] = collect_services(config.get("risk_services", ["TermService", "RemoteRegistry", "WinRM"]))
    if task_type in {"FULL_SCAN", "VERIFY_ADMINISTRATORS"}:
        evidence["local_administrators"] = collect_admins()
    if task_type in {"FULL_SCAN", "VERIFY_UPDATES"}:
        evidence["updates"] = collect_updates()
    if task_type in {"FULL_SCAN", "VERIFY_ANTIVIRUS"}:
        evidence["antivirus"] = collect_antivirus()
    if task_type in {"FULL_SCAN", "VERIFY_BACKUP"}:
        evidence["backup"] = collect_backup(config.get("backup_path", "C:\\Backups"))
    return evidence


def request_json(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def send_scan(config: dict[str, Any], task_type: str) -> dict[str, Any]:
    if task_type not in ALLOWED_TASKS:
        raise ValueError(f"Tarea no permitida: {task_type}")
    evidence = collect_evidence(config, task_type)
    return request_json(
        "POST",
        f"{config['api_url'].rstrip('/')}/api/agent/results",
        config["token"],
        {"device_id": config["device_id"], "scan_type": task_type, "evidence": evidence},
    )


def poll_once(config: dict[str, Any]) -> None:
    url = f"{config['api_url'].rstrip('/')}/api/agent/tasks?device_id={urllib.parse.quote(config['device_id'])}"
    tasks = request_json("GET", url, config["token"]).get("tasks", [])
    for task in tasks:
        send_scan(config, task["task_type"])
        request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/complete", config["token"], {})


def main() -> int:
    parser = argparse.ArgumentParser(description="Agente Windows CyberCheck MIPYME")
    parser.add_argument("--config", default="agent/agent_config.example.json")
    parser.add_argument("--scan", choices=sorted(ALLOWED_TASKS))
    parser.add_argument("--poll-once", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    try:
        if args.poll_once:
            poll_once(config)
        else:
            print(json.dumps(send_scan(config, args.scan or "FULL_SCAN"), indent=2))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"Error del agente: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
