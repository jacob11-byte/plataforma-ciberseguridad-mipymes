from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.core.modules import run_module
from agent.core.powershell import run_powershell
from agent.modules.eventlog import collect_security_events
from agent.modules.process_inventory import collect_processes
from agent.modules.security_controls import collect_security_controls
from agent.modules.software_inventory import collect_installed_software
from agent.modules.system_inventory import collect_system_inventory

AGENT_VERSION = "0.2.0"

ALLOWED_TASKS = {
    "FULL_SCAN",
    "VERIFY_FIREWALL",
    "VERIFY_PORTS",
    "VERIFY_SERVICES",
    "VERIFY_ADMINISTRATORS",
    "VERIFY_UPDATES",
    "VERIFY_ANTIVIRUS",
    "VERIFY_DEVICES",
    "VERIFY_BACKUP",
    "V2_SNAPSHOT",
    "VERIFY_SECURITY_CONTROLS",
    "VERIFY_SOFTWARE",
    "VERIFY_PROCESSES",
    "VERIFY_EVENTLOG",
}


def system_info() -> dict[str, Any]:
    inventory = collect_system_inventory()
    return {
        "hostname": inventory.get("hostname"),
        "ip_address": inventory.get("ip_address"),
        "os_version": inventory.get("os_version"),
        "windows_edition": inventory.get("windows_edition"),
        "architecture": inventory.get("architecture"),
    }


def windows_edition() -> str | None:
    if os.name != "nt":
        return None
    data = run_powershell(
        "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption | ConvertTo-Json -Compress"
    )
    return str(data) if data else None


def collect_firewall() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_supported", "error": "El agente solo consulta firewall real en Windows."}
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
        return [{"name": name, "running": None, "status": "not_supported"} for name in names]
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
        "company_name": config.get("company_name", "MIPYME Principal"),
        "registration_code": config["registration_code"],
        "hostname": info["hostname"],
        "os_version": info["os_version"],
        "windows_edition": info["windows_edition"],
        "architecture": info["architecture"],
        "ip_address": info["ip_address"],
        "agent_version": AGENT_VERSION,
    }
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(f"{config['api_url'].rstrip('/')}/api/register", data=data, method="POST")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    config["device_id"] = result["device_id"]
    config["token"] = result["token"]
    return result


def ensure_registered(config: dict[str, Any], config_path: Path) -> None:
    if config.get("device_id") and config.get("token"):
        return
    print("[OK] Registering new agent")
    result = register_device(config)
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(f"[OK] Device ID: {result['device_id']}")


def send_heartbeat(config: dict[str, Any]) -> dict[str, Any]:
    return request_json(
        "POST",
        f"{config['api_url'].rstrip('/')}/api/agent/heartbeat",
        config["token"],
        {
            "device_id": config["device_id"],
            "agent_version": AGENT_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def collect_updates() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_supported", "pending_count": None, "reboot_pending": None}
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
        return {"status": "not_supported", "enabled": None, "real_time": None}
    defender = run_powershell(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object "
        "AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,"
        "NISEnabled,AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated,"
        "QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime,"
        "FullScanAge,QuickScanAge,AntivirusSignatureAge,ComputerState,DefenderSignaturesOutOfDate,"
        "IsTamperProtected,OnAccessProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled | ConvertTo-Json -Compress"
    )
    preferences = run_powershell(
        "Get-MpPreference -ErrorAction SilentlyContinue | Select-Object "
        "DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,PUAProtection,"
        "MAPSReporting,SubmitSamplesConsent,ScanScheduleDay,ScanScheduleTime | ConvertTo-Json -Compress"
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
            "tamper_protected": defender.get("IsTamperProtected"),
            "on_access_protection": defender.get("OnAccessProtectionEnabled"),
            "behavior_monitor": defender.get("BehaviorMonitorEnabled"),
            "ioav_protection": defender.get("IoavProtectionEnabled"),
            "signatures_out_of_date": defender.get("DefenderSignaturesOutOfDate"),
            "preferences": preferences if isinstance(preferences, dict) and not preferences.get("error") else {},
            "threats": threat_rows,
            "active_threat_count": sum(1 for threat in threat_rows if isinstance(threat, dict) and threat.get("IsActive")),
        }
    if not isinstance(data, dict):
        return {"enabled": False, "real_time": False, "error": data}
    state = int(data.get("productState") or 0)
    return {"enabled": state != 0, "real_time": state != 0, "name": data.get("displayName"), "product_state": state}


def collect_connected_devices() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_supported", "devices": [], "usb_storage": [], "unsigned_drivers": []}
    devices = run_powershell(
        "$classes=@('USB','DiskDrive','Net','Camera','Bluetooth','HIDClass','Keyboard','Mouse','Ports','MEDIA'); "
        "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
        "Where-Object { $classes -contains $_.Class } | "
        "Select-Object -First 80 Class,FriendlyName,InstanceId,Status,Manufacturer | ConvertTo-Json -Compress"
    )
    usb_storage = run_powershell(
        "Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | "
        "Where-Object { $_.InterfaceType -eq 'USB' } | "
        "Select-Object Model,SerialNumber,Size,MediaType,InterfaceType | ConvertTo-Json -Compress"
    )
    unsigned_drivers = run_powershell(
        "Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | "
        "Where-Object { $_.IsSigned -eq $false -and $_.DeviceName } | "
        "Select-Object -First 30 DeviceName,Manufacturer,DriverVersion,InfName,IsSigned | ConvertTo-Json -Compress"
    )
    device_rows = devices if isinstance(devices, list) else ([devices] if isinstance(devices, dict) and not devices.get("error") else [])
    usb_rows = usb_storage if isinstance(usb_storage, list) else ([usb_storage] if isinstance(usb_storage, dict) and not usb_storage.get("error") else [])
    unsigned_rows = unsigned_drivers if isinstance(unsigned_drivers, list) else ([unsigned_drivers] if isinstance(unsigned_drivers, dict) and not unsigned_drivers.get("error") else [])
    device_errors = [
        item for item in device_rows
        if isinstance(item, dict) and str(item.get("Status", "")).upper() not in {"OK", "UNKNOWN", ""}
    ]
    return {
        "status": "ok",
        "devices": device_rows,
        "device_count": len(device_rows),
        "usb_storage": usb_rows,
        "usb_storage_count": len(usb_rows),
        "unsigned_drivers": unsigned_rows,
        "unsigned_driver_count": len(unsigned_rows),
        "device_errors": device_errors,
        "device_error_count": len(device_errors),
    }


def collect_backup(path: str) -> dict[str, Any]:
    if not path:
        return {"status": "not_configured", "exists": None}
    root = Path(path)
    if not root.exists():
        return {"status": "missing", "exists": False, "path": path}
    files = [p for p in root.rglob("*") if p.is_file()]
    if not files:
        return {"status": "empty", "exists": False, "path": path}
    latest = max(files, key=lambda p: p.stat().st_mtime)
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(latest.stat().st_mtime, timezone.utc)
    return {"status": "ok", "exists": True, "path": path, "latest_file": latest.name, "days_since_last_backup": age.days, "latest_size": latest.stat().st_size}


def collect_evidence(config: dict[str, Any], task_type: str) -> dict[str, Any]:
    started = time.perf_counter()
    module_status: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_version": AGENT_VERSION,
        "system_info": system_info(),
    }

    def collect_module(name: str, target_key: str, collector: Any) -> None:
        module_started = time.perf_counter()
        try:
            result = collector()
            evidence[target_key] = result
            has_error = isinstance(result, dict) and (bool(result.get("error")) or result.get("success") is False)
            module_status.append(
                {
                    "module": name,
                    "status": "error" if has_error else "ok",
                    "duration_ms": int((time.perf_counter() - module_started) * 1000),
                    "error": result.get("error") if isinstance(result, dict) else None,
                }
            )
        except Exception as exc:
            evidence[target_key] = {"status": "error", "error": str(exc)}
            module_status.append(
                {
                    "module": name,
                    "status": "error",
                    "duration_ms": int((time.perf_counter() - module_started) * 1000),
                    "error": str(exc),
                }
            )

    if task_type in {"FULL_SCAN", "VERIFY_FIREWALL"}:
        collect_module("firewall", "firewall", collect_firewall)
    if task_type in {"FULL_SCAN", "VERIFY_PORTS"}:
        collect_module("ports", "listening_ports", collect_ports)
    if task_type in {"FULL_SCAN", "VERIFY_SERVICES"}:
        collect_module("services", "services", lambda: collect_services(config.get("risk_services", ["TermService", "RemoteRegistry", "WinRM"])))
    if task_type in {"FULL_SCAN", "VERIFY_ADMINISTRATORS"}:
        collect_module("administrators", "local_administrators", collect_admins)
    if task_type in {"FULL_SCAN", "VERIFY_UPDATES"}:
        collect_module("updates", "updates", collect_updates)
    if task_type in {"FULL_SCAN", "VERIFY_ANTIVIRUS"}:
        collect_module("antivirus", "antivirus", collect_antivirus)
    if task_type in {"FULL_SCAN", "VERIFY_DEVICES"}:
        collect_module("connected_devices", "connected_devices", collect_connected_devices)
    if task_type in {"FULL_SCAN", "VERIFY_BACKUP"}:
        collect_module("backup", "backup", lambda: collect_backup(config.get("backup_path", "C:\\Backups")))
    if task_type in {"V2_SNAPSHOT", "FULL_SCAN"}:
        collect_module("system_inventory_v2", "system_inventory_v2", lambda: run_module(collect_system_inventory).to_dict())
        collect_module("security_controls", "security_controls", lambda: run_module(collect_security_controls).to_dict())
        collect_module("software_inventory", "software_inventory", lambda: run_module(collect_installed_software).to_dict())
        collect_module("process_inventory", "process_inventory", lambda: run_module(collect_processes).to_dict())
        collect_module("security_eventlog", "security_eventlog", lambda: run_module(collect_security_events).to_dict())
    if task_type == "VERIFY_SECURITY_CONTROLS":
        collect_module("security_controls", "security_controls", lambda: run_module(collect_security_controls).to_dict())
    if task_type == "VERIFY_SOFTWARE":
        collect_module("software_inventory", "software_inventory", lambda: run_module(collect_installed_software).to_dict())
    if task_type == "VERIFY_PROCESSES":
        collect_module("process_inventory", "process_inventory", lambda: run_module(collect_processes).to_dict())
    if task_type == "VERIFY_EVENTLOG":
        collect_module("security_eventlog", "security_eventlog", lambda: run_module(collect_security_events).to_dict())
    evidence["scan_metadata"] = {
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "modules_success": sum(1 for item in module_status if item["status"] == "ok"),
        "modules_error": sum(1 for item in module_status if item["status"] == "error"),
        "modules": module_status,
    }
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
    print(f"[SCAN] Starting {task_type}")
    evidence = collect_evidence(config, task_type)
    result = request_json(
        "POST",
        f"{config['api_url'].rstrip('/')}/api/agent/results",
        config["token"],
        {"device_id": config["device_id"], "scan_type": task_type, "evidence": evidence},
    )
    print("[OK] Results sent to API")
    return result


def poll_once(config: dict[str, Any], max_tasks: int = 3) -> None:
    send_heartbeat(config)
    print("[OK] Heartbeat sent")
    url = (
        f"{config['api_url'].rstrip('/')}/api/agent/tasks"
        f"?device_id={urllib.parse.quote(config['device_id'])}&max_tasks={max_tasks}"
    )
    tasks = request_json("GET", url, config["token"]).get("tasks", [])[:max_tasks]
    if not tasks:
        print("No hay tareas pendientes.")
        return
    seen_task_types = set()
    for task in tasks:
        try:
            if task["task_type"] in seen_task_types:
                print(f"[TASK] Skipping duplicate {task['id']}: {task['task_type']}")
                request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/complete", config["token"], {})
                continue
            seen_task_types.add(task["task_type"])
            print(f"[TASK] Executing {task['id']}: {task['task_type']}")
            send_scan(config, task["task_type"])
            request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/complete", config["token"], {})
            print(f"[OK] Task {task['id']} completed")
        except Exception as exc:
            print(f"[ERROR] Task {task['id']} failed: {exc}", file=sys.stderr)
            try:
                request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/fail", config["token"], {})
            except Exception:
                pass


def poll_loop(config: dict[str, Any], interval_seconds: int, max_tasks: int) -> None:
    print(f"[TASK] Waiting for tasks every {interval_seconds} seconds")
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
    parser.add_argument("--max-tasks", type=int, default=10)
    parser.add_argument("--register", action="store_true")
    args = parser.parse_args()
    config_path = Path(args.config)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if os.getenv("API_BASE_URL"):
        config["api_url"] = os.getenv("API_BASE_URL")
    try:
        print("[OK] Agent started")
        info = system_info()
        print(f"[OK] Computer: {info['hostname']}")
        ensure_registered(config, config_path)
        print(f"[OK] Device ID: {config['device_id']}")
        send_heartbeat(config)
        print("[OK] API connected")
        print("[OK] Heartbeat sent")
        if args.register:
            print(json.dumps({"device_id": config["device_id"], "registered": True}, indent=2))
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
