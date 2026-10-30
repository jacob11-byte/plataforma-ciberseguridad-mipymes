from __future__ import annotations

import argparse
import json
import logging
import os
import random
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.core.modules import run_module
from agent.core.powershell import run_powershell
from agent.outbox import Outbox
from agent.modules.eventlog import collect_security_detections, collect_security_events
from agent.modules.hardening import collect_hardening
from agent.modules.process_inventory import collect_processes
from agent.modules.security_controls import collect_security_controls
from agent.modules.software_inventory import collect_installed_software
from agent.modules.system_inventory import collect_system_inventory

AGENT_VERSION = "0.8.1"
LOGGER = logging.getLogger("cybercheck.agent")
HTTP_TIMEOUT_SECONDS = 60
HTTP_MAX_ATTEMPTS = 3

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
    "VERIFY_HARDENING",
}
# The service runs a full scan on its own on this cadence, even when nobody
# requests one from the panel. Overridable with "auto_scan_hours" (0 = off).
DEFAULT_AUTO_SCAN_HOURS = 12


class AgentAlreadyRunning(RuntimeError):
    pass


class AgentInstanceLock:
    """Cross-process lock that prevents duplicate scans and enrollment races."""

    def __init__(self, config_path: Path) -> None:
        self.path = config_path.with_name(f".{config_path.name}.lock")
        self.handle: Any | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            self.handle.close()
            self.handle = None
            raise AgentAlreadyRunning("Ya existe una instancia del agente para esta configuracion") from exc

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None


def configure_logging() -> None:
    if LOGGER.handlers:
        return
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    log_roots: list[Path] = []
    if os.environ.get("CYBERCHECK_LOG_DIR"):
        log_roots.append(Path(os.environ["CYBERCHECK_LOG_DIR"]))
    if os.environ.get("PROGRAMDATA"):
        log_roots.append(Path(os.environ["PROGRAMDATA"]) / "CyberCheck" / "logs")
    log_roots.extend([
        Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir())) / "CyberCheck" / "logs",
        Path(tempfile.gettempdir()) / "CyberCheck" / "logs",
    ])
    for root in log_roots:
        try:
            root.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(root / "agent.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            LOGGER.addHandler(handler)
            break
        except OSError:
            continue
    if sys.stderr is not None:
        LOGGER.addHandler(logging.StreamHandler(sys.stderr))


def log_failure(context: str, exc: Exception, config: dict[str, Any] | None = None) -> None:
    message = redact_error(exc, config)
    LOGGER.error("%s: %s: %s", context, type(exc).__name__, message[:500])


def redact_error(exc: Exception, config: dict[str, Any] | None = None) -> str:
    message = str(exc)
    if config:
        for key in ("token", "registration_code"):
            secret = config.get(key)
            if isinstance(secret, str) and secret:
                message = message.replace(secret, "[REDACTED]")
    return message[:500]


def load_agent_config(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("La configuracion debe ser un objeto JSON")
    if os.getenv("API_BASE_URL"):
        config["api_url"] = os.environ["API_BASE_URL"]
    validate_agent_config(config)
    config["_config_path"] = str(config_path)
    return config


def validate_agent_config(config: dict[str, Any]) -> None:
    """Reject configurations that would expose credentials or fail unpredictably."""
    api_url = config.get("api_url")
    if not isinstance(api_url, str) or not api_url.strip():
        raise ValueError("api_url es obligatorio")
    parsed = urlsplit(api_url.strip())
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("api_url debe ser un origen sin credenciales, ruta, consulta ni fragmento")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in local_hosts):
        raise ValueError("api_url debe usar HTTPS; HTTP solo se permite para desarrollo local")

    has_device = isinstance(config.get("device_id"), str) and bool(config["device_id"].strip())
    has_token = isinstance(config.get("token"), str) and bool(config["token"].strip())
    if has_device != has_token:
        raise ValueError("device_id y token deben existir juntos")
    registered = has_device and has_token
    if not registered and not (
        isinstance(config.get("registration_code"), str) and config["registration_code"].strip()
    ):
        raise ValueError("registration_code es obligatorio para registrar el agente")
    services = config.get("risk_services", ["TermService", "RemoteRegistry", "WinRM"])
    if not isinstance(services, list) or not services or not all(
        isinstance(item, str) and item.strip() for item in services
    ):
        raise ValueError("risk_services debe ser una lista no vacia de nombres de servicio")
    if "authorized_local_admins" in config and not (
        isinstance(config["authorized_local_admins"], list)
        and all(isinstance(item, str) and item.strip() for item in config["authorized_local_admins"])
    ):
        raise ValueError("authorized_local_admins debe ser una lista de cuentas")


def collection_error(value: Any) -> dict[str, str] | None:
    if isinstance(value, dict) and "error" in value:
        return {"status": "error", "error": str(value.get("error") or "La consulta de Windows fallo.")}
    return None


def parse_windows_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    return None


def service_enum_name(value: Any, mapping: dict[int, str]) -> str | None:
    if isinstance(value, str) and value in mapping.values():
        return value
    try:
        return mapping.get(int(value))
    except (TypeError, ValueError):
        return None


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
    error = collection_error(data)
    if error:
        return error
    profiles = data if isinstance(data, list) else [data]
    result = {}
    for profile in profiles:
        if isinstance(profile, dict):
            result[str(profile.get("Name", "")).lower()] = parse_windows_bool(profile.get("Enabled"))
    if not all(isinstance(result.get(name), bool) for name in ("domain", "private", "public")):
        return {"status": "error", "error": "No se pudieron leer los tres perfiles del firewall."}
    return {"domain": result.get("domain"), "private": result.get("private"), "public": result.get("public")}


def collect_ports() -> list[dict[str, Any]] | dict[str, str]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
    )
    error = collection_error(data)
    if error:
        return error
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


def collect_services(names: list[str]) -> list[dict[str, Any]] | dict[str, str]:
    if os.name != "nt":
        return [{"name": name, "running": None, "status": "not_supported"} for name in names]
    quoted = ",".join("'" + name.replace("'", "''") + "'" for name in names)
    data = run_powershell(
        f"Get-Service -Name {quoted} -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType | ConvertTo-Json -Compress"
    )
    error = collection_error(data)
    if error:
        return error
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    status_names = {
        1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running",
        5: "ContinuePending", 6: "PausePending", 7: "Paused",
    }
    start_names = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
    services = []
    for row in rows:
        status = service_enum_name(row.get("Status"), status_names)
        start_type = service_enum_name(row.get("StartType"), start_names)
        if status is None:
            return {"status": "error", "error": "No se pudo interpretar el estado de un servicio."}
        services.append({
            "name": row.get("Name"), "status": status, "start_type": start_type,
            "running": status == "Running",
        })
    return services


def collect_admins() -> list[str] | dict[str, str]:
    if os.name != "nt":
        return []
    data = run_powershell(
        "$group = Get-LocalGroup | Where-Object { $_.SID -eq 'S-1-5-32-544' } | Select-Object -First 1; "
        "if ($group) { Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name | ConvertTo-Json -Compress }"
    )
    if data is None or (isinstance(data, dict) and data.get("error")):
        data = run_powershell(
            "net localgroup Administradores | Select-Object -Skip 6 | "
            "Where-Object { $_ -and $_ -notmatch 'completado|completed|---' } | ConvertTo-Json -Compress"
        )
    if data is None or (isinstance(data, dict) and data.get("error")):
        data = run_powershell(
            "net localgroup Administrators | Select-Object -Skip 6 | "
            "Where-Object { $_ -and $_ -notmatch 'completed|completado|---' } | ConvertTo-Json -Compress"
        )
    error = collection_error(data)
    if error:
        return error
    if data is None:
        return {"status": "error", "error": "No se pudo leer el grupo local de administradores."}
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
    request.add_header("User-Agent", f"CyberCheck-Agent/{AGENT_VERSION}")
    result = open_json_with_retry(request)
    config["device_id"] = result["device_id"]
    config["token"] = result["token"]
    return result


def write_agent_config(config: dict[str, Any], config_path: Path) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=config_path.parent,
            prefix=f".{config_path.name}.", suffix=".tmp", delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            # Keys starting with "_" are runtime-only (e.g. "_config_path").
            json.dump({k: v for k, v in config.items() if not k.startswith("_")}, temporary, indent=2)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, config_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def ensure_registered(config: dict[str, Any], config_path: Path) -> None:
    if config.get("device_id") and config.get("token"):
        if config.pop("registration_code", None) is not None:
            write_agent_config(config, config_path)
            LOGGER.info("Codigo de registro eliminado de la configuracion ya enrolada")
        return
    LOGGER.info("Registrando nuevo agente")
    result = register_device(config)
    config.pop("registration_code", None)
    write_agent_config(config, config_path)
    LOGGER.info("Agente registrado: %s", result["device_id"])


def rotate_credential(config: dict[str, Any]) -> bool:
    """Swap the device token for a fresh one issued by the server.

    The new token is persisted before it is used. If the write fails the old
    token is kept; the server leaves it valid for a grace period and will ask
    again on the next heartbeat.
    """
    config_path = config.get("_config_path")
    if not config_path:
        LOGGER.warning("Rotacion de credencial omitida: configuracion sin ruta persistente")
        return False
    result = request_json(
        "POST",
        f"{config['api_url'].rstrip('/')}/api/agent/rotate-credential",
        config["token"],
        {"device_id": config["device_id"]},
    )
    new_token = result.get("token")
    if not isinstance(new_token, str) or len(new_token) < 20:
        raise ValueError("La API devolvio una credencial invalida")
    write_agent_config({**config, "token": new_token}, Path(config_path))
    config["token"] = new_token
    LOGGER.info("Credencial del agente renovada")
    return True


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
    # One search returns both the count and which updates are missing, so the
    # panel can name the KB and its severity instead of only a number.
    pending = run_powershell(
        "$s=New-Object -ComObject Microsoft.Update.Session; "
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software' and IsHidden=0\"); "
        "[pscustomobject]@{ Count = $r.Updates.Count; Items = @($r.Updates | Select-Object -First 30 | ForEach-Object { "
        "[pscustomobject]@{ Title = [string]$_.Title; "
        "KB = (@($_.KBArticleIDs) | ForEach-Object { 'KB' + $_ }) -join ','; "
        "CVEs = (@($_.CveIDs) | ForEach-Object { [string]$_ }) -join ','; "
        "Severity = [string]$_.MsrcSeverity; "
        "Security = [bool](@($_.Categories) | Where-Object { $_.Name -match 'Security|Seguridad' }) } }) "
        "} | ConvertTo-Json -Compress -Depth 4",
        timeout=240,
    )
    for value in (reboot, pending):
        error = collection_error(value)
        if error:
            return error
    if not isinstance(reboot, bool) or not isinstance(pending, dict):
        return {"status": "error", "error": "Windows Update devolvio datos incompletos."}
    try:
        pending_count = int(pending.get("Count"))
    except (TypeError, ValueError):
        return {"status": "error", "error": "No se pudo leer el numero de actualizaciones pendientes."}
    items = pending.get("Items") or []
    items = items if isinstance(items, list) else [items]
    return {
        "pending_count": pending_count,
        "reboot_pending": reboot,
        "pending_updates": [
            {
                "title": item.get("Title"),
                "kb": item.get("KB") or None,
                "cves": [cve.strip() for cve in str(item.get("CVEs") or "").split(",") if cve.strip().upper().startswith("CVE-")],
                "severity": item.get("Severity") or None,
                "security": bool(item.get("Security")),
            }
            for item in items
            if isinstance(item, dict)
        ],
    }


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
        if not defender.get("AntivirusEnabled") and isinstance(data, dict) and data.get("displayName"):
            product_name = str(data["displayName"])
            if "defender" not in product_name.lower():
                return {
                    "status": "error",
                    "enabled": None,
                    "real_time": None,
                    "name": product_name,
                    "error": "Hay un antivirus de terceros; el estado de proteccion requiere verificacion especifica.",
                }
        collection_errors: dict[str, str] = {}
        preferences_error = collection_error(preferences)
        threats_error = collection_error(threats)
        if preferences_error:
            collection_errors["preferences"] = preferences_error["error"]
        if threats_error:
            collection_errors["threats"] = threats_error["error"]
        threat_rows = (
            threats if isinstance(threats, list)
            else [threats] if isinstance(threats, dict) and not threats.get("error")
            else []
        )
        result = {
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
            "preferences": preferences if isinstance(preferences, dict) and not preferences.get("error") else None,
            "threats": None if threats_error else threat_rows,
            "active_threat_count": None if threats_error else sum(
                1 for threat in threat_rows if isinstance(threat, dict) and threat.get("IsActive")
            ),
        }
        if collection_errors:
            result["collection_errors"] = collection_errors
        return result
    error = collection_error(data)
    if error:
        return error
    if not isinstance(data, dict) or not data.get("displayName"):
        return {"status": "error", "error": "No se pudo determinar el estado del antivirus."}
    state = int(data.get("productState") or 0)
    return {
        "status": "error",
        "enabled": None,
        "real_time": None,
        "name": data.get("displayName"),
        "product_state": state,
        "error": "El valor de SecurityCenter2 no prueba que la proteccion en tiempo real este activa.",
    }


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
    for value in (devices, usb_storage, unsigned_drivers):
        error = collection_error(value)
        if error:
            return error
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
    if task_type in {"FULL_SCAN", "VERIFY_ADMINISTRATORS"} and "authorized_local_admins" in config:
        allowed_admins = config["authorized_local_admins"]
        if isinstance(allowed_admins, list) and all(isinstance(item, str) for item in allowed_admins):
            evidence["authorized_local_admins"] = allowed_admins

    def collect_module(name: str, target_key: str, collector: Any) -> None:
        module_started = time.perf_counter()
        try:
            result = collector()
            evidence[target_key] = result
            has_error = isinstance(result, dict) and (bool(result.get("error")) or result.get("success") is False)
            partial_errors = result.get("collection_errors") if isinstance(result, dict) else None
            module_status.append(
                {
                    "module": name,
                    "status": "error" if has_error else "partial" if partial_errors else "ok",
                    "duration_ms": int((time.perf_counter() - module_started) * 1000),
                    "error": (
                        result.get("error") if isinstance(result, dict) and result.get("error")
                        else "; ".join(f"{key}: {value}" for key, value in partial_errors.items())
                        if isinstance(partial_errors, dict)
                        else None
                    ),
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
    if task_type in {"FULL_SCAN", "VERIFY_HARDENING"}:
        collect_module("hardening", "hardening", lambda: run_module(collect_hardening).to_dict())
    if task_type in {"FULL_SCAN", "VERIFY_EVENTLOG"}:
        collect_module("security_detections", "security_detections", collect_security_detections)
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
        "modules_error": sum(1 for item in module_status if item["status"] != "ok"),
        "modules": module_status,
    }
    return evidence


def retry_delay(attempt: int, error: urllib.error.HTTPError | None = None) -> float:
    if error is not None:
        retry_after = error.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return min(30.0, max(1.0, float(retry_after)))
    return min(15.0, (2 ** attempt) + random.uniform(0.0, 1.0))


def open_json_with_retry(request: urllib.request.Request) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(HTTP_MAX_ATTEMPTS):
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("La API no devolvio un objeto JSON")
                return payload
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code < 500 and exc.code != 429:
                raise
            if attempt + 1 >= HTTP_MAX_ATTEMPTS:
                raise
            time.sleep(retry_delay(attempt, exc))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt + 1 >= HTTP_MAX_ATTEMPTS:
                raise
            time.sleep(retry_delay(attempt))
    raise RuntimeError("No se pudo completar la solicitud") from last_error


def request_json(method: str, url: str, token: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", f"CyberCheck-Agent/{AGENT_VERSION}")
    return open_json_with_retry(request)


def is_transient_request_error(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(
        exc,
        (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError),
    )


def result_outbox() -> Outbox:
    return Outbox()


def flush_outbox(config: dict[str, Any], limit: int = 20) -> dict[str, int]:
    outbox = result_outbox()
    sent = 0
    results_url = f"{config['api_url'].rstrip('/')}/api/agent/results"
    for item in outbox.ready(limit=limit):
        try:
            try:
                request_json("POST", results_url, config["token"], item.payload)
            except urllib.error.HTTPError as exc:
                # The task may have been cancelled or failed while the device
                # was offline; keep the evidence as an ad-hoc scan instead of
                # discarding it.
                if exc.code != 409 or item.payload.get("task_id") is None:
                    raise
                LOGGER.warning(
                    "La tarea %s ya no acepta resultados; se entrega como verificacion independiente",
                    item.payload.get("task_id"),
                )
                request_json("POST", results_url, config["token"], {**item.payload, "task_id": None})
        except Exception as exc:
            message = f"{type(exc).__name__}: {redact_error(exc, config)}"
            if is_transient_request_error(exc):
                outbox.mark_retry(item.id, message, item.attempts)
                LOGGER.warning("La API sigue sin responder; quedan resultados en la cola offline")
                break
            outbox.mark_dead(item.id, message)
            LOGGER.error("Resultado %s movido a revision manual: %s", item.request_id, message)
            continue
        outbox.mark_sent(item.id)
        sent += 1
        LOGGER.info("Resultado offline entregado: %s", item.request_id)
    stats = outbox.stats()
    return {"sent": sent, "pending": stats["pending"], "dead": stats["dead"]}


def send_scan(
    config: dict[str, Any],
    task_type: str,
    *,
    task_id: int | None = None,
    request_id: str | None = None,
    queue_on_failure: bool = True,
) -> dict[str, Any]:
    if task_type not in ALLOWED_TASKS:
        raise ValueError(f"Tarea no permitida: {task_type}")
    LOGGER.info("Iniciando verificacion %s", task_type)
    evidence = collect_evidence(config, task_type)
    result_request_id = request_id or (
        f"task-id:{task_id}" if task_id is not None else str(uuid.uuid4())
    )
    payload = {
        "device_id": config["device_id"],
        "scan_type": task_type,
        "evidence": evidence,
        "request_id": result_request_id,
        "task_id": task_id,
    }
    try:
        result = request_json(
            "POST",
            f"{config['api_url'].rstrip('/')}/api/agent/results",
            config["token"],
            payload,
        )
    except Exception as exc:
        if not queue_on_failure or not is_transient_request_error(exc):
            raise
        inserted = result_outbox().enqueue(result_request_id, payload)
        LOGGER.warning(
            "Resultado guardado en cola offline (%s): %s",
            "nuevo" if inserted else "ya existente",
            result_request_id,
        )
        return {"queued": True, "request_id": result_request_id}
    LOGGER.info("Resultado enviado: %s", task_type)
    return result


FAILED_SCAN_RETRY_SECONDS = 60 * 60


def _state_path(config: dict[str, Any]) -> Path | None:
    config_path = config.get("_config_path")
    return Path(config_path).with_name("agent_state.json") if config_path else None


def load_agent_state(config: dict[str, Any]) -> dict[str, Any]:
    path = _state_path(config)
    if path is None:
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return state if isinstance(state, dict) else {}


def record_full_scan(config: dict[str, Any], ok: bool, now: float | None = None) -> None:
    path = _state_path(config)
    if path is None:
        return
    state = load_agent_state(config)
    state.update({"last_full_scan": time.time() if now is None else now, "last_full_scan_ok": ok})
    try:
        write_agent_config(state, path)
    except OSError as exc:
        log_failure("No se pudo guardar el estado del agente", exc, config)


def scheduled_scan_due(config: dict[str, Any], now: float | None = None) -> bool:
    """True when the device has not been fully reviewed recently.

    A newly installed agent has no state, so its first cycle performs a full
    scan immediately; failed attempts are retried after an hour.
    """
    if _state_path(config) is None:
        return False
    try:
        hours = float(config.get("auto_scan_hours", DEFAULT_AUTO_SCAN_HOURS))
    except (TypeError, ValueError):
        hours = DEFAULT_AUTO_SCAN_HOURS
    if hours <= 0:
        return False
    state = load_agent_state(config)
    last = state.get("last_full_scan")
    if not isinstance(last, (int, float)):
        return True
    interval = hours * 3600 if state.get("last_full_scan_ok", True) else FAILED_SCAN_RETRY_SECONDS
    return (time.time() if now is None else now) - last >= interval


def run_scheduled_scan(config: dict[str, Any]) -> None:
    if not scheduled_scan_due(config):
        return
    LOGGER.info("Ejecutando revision completa programada")
    try:
        send_scan(config, "FULL_SCAN")
    except Exception as exc:
        record_full_scan(config, ok=False)
        log_failure("Revision programada fallida; se reintentara en una hora", exc, config)
        return
    record_full_scan(config, ok=True)


def poll_once(config: dict[str, Any], max_tasks: int = 3) -> None:
    queue_status = flush_outbox(config)
    if queue_status["sent"]:
        LOGGER.info("Resultados recuperados de la cola: %s", queue_status["sent"])
    heartbeat = send_heartbeat(config)
    LOGGER.info("Heartbeat enviado")
    if heartbeat.get("rotate_credential"):
        try:
            rotate_credential(config)
        except Exception as exc:
            log_failure("No se pudo renovar la credencial; se reintentara", exc, config)
    url = (
        f"{config['api_url'].rstrip('/')}/api/agent/tasks"
        f"?device_id={urllib.parse.quote(config['device_id'])}&max_tasks={max_tasks}"
    )
    tasks = request_json("GET", url, config["token"]).get("tasks", [])[:max_tasks]
    if not tasks:
        LOGGER.info("Sin tareas pendientes")
    for task in tasks:
        try:
            LOGGER.info("Ejecutando tarea %s: %s", task["id"], task["task_type"])
            result = send_scan(config, task["task_type"], task_id=int(task["id"]))
            if task["task_type"] == "FULL_SCAN":
                record_full_scan(config, ok=True)
            if result.get("queued"):
                LOGGER.info("Tarea %s queda pendiente hasta recuperar conectividad", task["id"])
                continue
            request_json("POST", f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/complete", config["token"], {})
            LOGGER.info("Tarea completada: %s", task["id"])
        except urllib.error.HTTPError as exc:
            log_failure(f"Tarea {task.get('id', '?')} recibio HTTP {exc.code}", exc, config)
            if exc.code < 500 and exc.code != 429:
                try:
                    request_json(
                        "POST",
                        f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/fail",
                        config["token"],
                        {"error": f"HTTP {exc.code}"},
                    )
                except Exception:
                    pass
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Leave the task delivered. The server lease makes it available
            # again after a transient connectivity or process failure.
            log_failure(f"Tarea {task.get('id', '?')} se reintentara", exc, config)
        except Exception as exc:
            log_failure(f"Tarea {task.get('id', '?')} fallida", exc, config)
            try:
                request_json(
                    "POST",
                    f"{config['api_url'].rstrip('/')}/api/agent/tasks/{task['id']}/fail",
                    config["token"],
                    {"error": f"{type(exc).__name__}: {str(exc)[:400]}"},
                )
            except Exception:
                pass
    run_scheduled_scan(config)


def poll_loop(config: dict[str, Any], interval_seconds: int, max_tasks: int) -> None:
    LOGGER.info("Consultando tareas cada %s segundos", interval_seconds)
    while True:
        try:
            poll_once(config, max_tasks=max_tasks)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log_failure("No se pudo consultar el servidor; se reintentara", exc, config)
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
    configure_logging()
    config_path = Path(args.config)
    config: dict[str, Any] = {}
    instance_lock = AgentInstanceLock(config_path)
    try:
        instance_lock.acquire()
        if args.interval < 1 or args.max_tasks < 1:
            raise ValueError("--interval y --max-tasks deben ser mayores que cero")
        config = load_agent_config(config_path)
        LOGGER.info("Agente iniciado en %s", socket.gethostname())
        ensure_registered(config, config_path)
        if args.register:
            send_heartbeat(config)
            if sys.stdout is not None:
                print(json.dumps({"device_id": config["device_id"], "registered": True}, indent=2))
        elif args.loop:
            poll_loop(config, interval_seconds=args.interval, max_tasks=args.max_tasks)
        elif args.poll_once:
            poll_once(config, max_tasks=args.max_tasks)
        else:
            send_heartbeat(config)
            result = send_scan(config, args.scan or "FULL_SCAN")
            if sys.stdout is not None:
                print(json.dumps(result, indent=2))
    except AgentAlreadyRunning:
        LOGGER.info("Otra instancia del agente ya esta trabajando; esta ejecucion termina sin error")
        return 0
    except Exception as exc:
        log_failure("Error del agente", exc, config)
        return 1
    finally:
        instance_lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
