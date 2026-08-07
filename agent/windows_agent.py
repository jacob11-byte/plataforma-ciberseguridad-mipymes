from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
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
    ip_address = None
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip_address = None
    return {
        "hostname": socket.gethostname(),
        "ip_address": ip_address,
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
        {
            "address": row.get("LocalAddress"),
            "port": row.get("LocalPort"),
            "process_id": row.get("OwningProcess"),
            "process_name": process_name(row.get("OwningProcess")),
        }
        for row in rows
    ]


def process_name(process_id: Any) -> str | None:
    if os.name != "nt" or process_id in {None, ""}:
        return None
    try:
        pid = int(process_id)
    except (TypeError, ValueError):
        return None
    data = run_powershell(
        f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty ProcessName | ConvertTo-Json -Compress"
    )
    return str(data) if data else None


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
        "$group = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1; "
        "if ($group) { Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress }"
    )
    if isinstance(data, dict) and data.get("error"):
        data = run_powershell(
            "net localgroup Administradores | Select-Object -Skip 6 | "
            "Where-Object { $_ -and $_ -notmatch 'completado|completed|---' } | ConvertTo-Json -Compress"
        )
    if isinstance(data, dict) and data.get("error"):
        data = run_powershell(
            "net localgroup Administrators | Select-Object -Skip 6 | "
            "Where-Object { $_ -and $_ -notmatch 'completed|completado|---' } | ConvertTo-Json -Compress"
        )
    if isinstance(data, list):
        return [str(item).strip() for item in data if str(item).strip()]
    return [str(data).strip()] if data else []


def register_device(config: dict[str, Any]) -> dict[str, Any]:
    info = system_info()
    body = {
        "company_name": config.get("company_name", "MIPYME Demo"),
        "device_id": config["device_id"],
        "device_name": config.get("device_name", info["hostname"]),
        "os_version": info["os_version"],
        "architecture": info["architecture"],
        "ip_address": info["ip_address"],
    }
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(f"{config['api_url'].rstrip('/')}/api/register", data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    config["device_id"] = result["device_id"]
    config["token"] = result["token"]
    return result


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
    defender = run_powershell(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object "
        "AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,"
        "NISEnabled,AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated,"
        "QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime,"
        "FullScanAge,QuickScanAge,AntivirusSignatureAge,ComputerState | ConvertTo-Json -Compress"
    )
    threats = run_powershell(
        "Get-MpThreat -ErrorAction SilentlyContinue | Select-Object ThreatName,SeverityID,CategoryID,DidThreatExecute,IsActive,Resources | ConvertTo-Json -Compress"
    )
    data = run_powershell(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object -First 1 displayName,productState | ConvertTo-Json -Compress"
    )
    if isinstance(defender, dict) and not defender.get("error"):
        threat_rows = threats if isinstance(threats, list) else ([threats] if isinstance(threats, dict) and not threats.get("error") else [])
        return {
            "enabled": bool(defender.get("AntivirusEnabled")),
            "real_time": bool(defender.get("RealTimeProtectionEnabled")),
            "name": "Microsoft Defender",
            "antispyware_enabled": defender.get("AntispywareEnabled"),
            "network_inspection_enabled": defender.get("NISEnabled"),
            "signature_age_days": defender.get("AntivirusSignatureAge"),
            "signature_last_updated": defender.get("AntivirusSignatureLastUpdated"),
            "quick_scan_age_days": defender.get("QuickScanAge"),
            "quick_scan_end_time": defender.get("QuickScanEndTime"),
            "full_scan_age_days": defender.get("FullScanAge"),
            "full_scan_end_time": defender.get("FullScanEndTime"),
            "computer_state": defender.get("ComputerState"),
            "threats": threat_rows,
            "active_threat_count": sum(1 for threat in threat_rows if isinstance(threat, dict) and threat.get("IsActive")),
        }
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


def poll_once(config: dict[str, Any], max_tasks: int = 3) -> None:
    url = f"{config['api_url'].rstrip('/')}/api/agent/tasks?device_id={urllib.parse.quote(config['device_id'])}"
    tasks = request_json("GET", url, config["token"]).get("tasks", [])[:max_tasks]
    if not tasks:
        print("No hay tareas pendientes.")
        return
    for task in tasks:
        try:
            print(f"Ejecutando tarea {task['id']}: {task['task_type']}")
            send_scan(config, task["task_type"])
            request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/complete", config["token"], {})
            print(f"Tarea {task['id']} completada.")
        except Exception as exc:
            print(f"Tarea {task['id']} fallo: {exc}", file=sys.stderr)
            try:
                request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/fail", config["token"], {})
            except Exception:
                pass


def poll_loop(config: dict[str, Any], interval_seconds: int, max_tasks: int) -> None:
    print(f"Agente activo. Consultando tareas cada {interval_seconds} segundos.")
    while True:
        poll_once(config, max_tasks=max_tasks)
        time.sleep(interval_seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Agente Windows CyberCheck MIPYME")
    parser.add_argument("--config", default="agent/agent_config.example.json")
    parser.add_argument("--scan", choices=sorted(ALLOWED_TASKS))
    parser.add_argument("--poll-once", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--max-tasks", type=int, default=3)
    parser.add_argument("--register", action="store_true")
    args = parser.parse_args()
    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    try:
        if args.register:
            result = register_device(config)
            config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
            print(json.dumps(result, indent=2))
        elif args.loop:
            poll_loop(config, interval_seconds=args.interval, max_tasks=args.max_tasks)
        elif args.poll_once:
            poll_once(config, max_tasks=args.max_tasks)
        else:
            print(json.dumps(send_scan(config, args.scan or "FULL_SCAN"), indent=2))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"Error del agente: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
