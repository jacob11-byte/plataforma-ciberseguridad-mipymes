"""Near-real-time security telemetry for the Windows service.

Every POLL_SECONDS a single PowerShell call collects new security events and
a snapshot of processes, listening ports and USB drives. A pure-Python
``Classifier`` turns the differences into events, which are pushed to the API
immediately (they appear in the panel's live feed within seconds).

Only the facts needed to explain an event are sent; window titles, file
contents and keystrokes are never collected.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable

from agent.core.powershell import run_powershell

LOGGER = logging.getLogger("cybercheck.agent.realtime")

POLL_SECONDS = 30
BATCH_SIZE = 50
MAX_EVENTS_PER_CYCLE = 40
PENDING_LIMIT = 500
BURST_WINDOW_SECONDS = 300
BURST_COOLDOWN_SECONDS = 600
SIGNATURE_CHECKS_PER_CYCLE = 5

ALL_INTERFACES = {"0.0.0.0", "::", "[::]", "*"}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 5900: "VNC", 5901: "VNC", 6379: "Redis",
               11211: "Memcached", 27017: "MongoDB", 9200: "Elasticsearch"}
USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\descargas\\", "\\users\\public\\",
                 "\\desktop\\", "\\escritorio\\", "\\programdata\\", "\\$recycle.bin\\")
LOGON_TYPES = {"2": "teclado", "3": "red", "5": "servicio", "7": "desbloqueo", "8": "red con texto claro",
               "10": "escritorio remoto (RDP)", "11": "credenciales en cache"}
ADMINS_SID_SUFFIX = "S-1-5-32-544"

SNAPSHOT_SCRIPT = r"""
$since = [datetime]::Parse('__SINCE__', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
$out = New-Object System.Collections.ArrayList
function Add-Row($log, $e, $fields) {
  $p = $e.Properties
  $row = [ordered]@{ log = $log; record_id = [string]$e.RecordId; event_id = $e.Id; time_created = $e.TimeCreated.ToUniversalTime().ToString('o') }
  foreach ($k in $fields.Keys) { $i = $fields[$k]; if ($p.Count -gt $i) { $row[$k] = [string]$p[$i].Value } }
  [void]$out.Add([pscustomobject]$row)
}
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4625} -MaxEvents 300 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'Security' $_ ([ordered]@{ target_user = 5; sub_status = 9; logon_type = 10; workstation = 13; source_ip = 19 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4720} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'Security' $_ ([ordered]@{ target_user = 0; subject_user = 4 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4732} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'Security' $_ ([ordered]@{ member_sid = 1; group = 2; group_sid = 4; subject_user = 6 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=4740} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'Security' $_ ([ordered]@{ target_user = 0; caller_computer = 1 }) }
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$since; Id=1102} -MaxEvents 10 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'Security' $_ ([ordered]@{ subject_user = 1 }) }
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Id=7045} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object { Add-Row 'System' $_ ([ordered]@{ service_name = 0; image_path = 1; start_type = 3; account = 4 }) }
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since; Id=1116,1117,1118,1119,5001} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $m = ($_.Message -split '\r?\n' | Where-Object { $_ } | Select-Object -First 8) -join ' | '
    [void]$out.Add([pscustomobject]@{ log = 'Defender'; record_id = [string]$_.RecordId; event_id = $_.Id; time_created = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $m })
  }
$procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ pid = $_.ProcessId; ppid = $_.ParentProcessId; name = $_.Name; path = $_.ExecutablePath
    created = $(if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') }) } })
$usb = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceType -eq 'USB' } | ForEach-Object {
  [pscustomobject]@{ model = $_.Model; serial = ([string]$_.SerialNumber).Trim(); size = $_.Size } })
$ports = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ address = $_.LocalAddress; port = $_.LocalPort; pid = $_.OwningProcess } })
[pscustomobject]@{ events = @($out); processes = $procs; usb = $usb; ports = $ports } | ConvertTo-Json -Compress -Depth 4
"""


def parse_time(value: Any) -> float:
    """Epoch seconds from the ISO strings PowerShell emits (7 fractional digits)."""
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(value or "")).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return time.time()
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def user_writable(path: Any) -> bool:
    return any(marker in "\\" + str(path or "").lower().replace("/", "\\") for marker in USER_WRITABLE)


def _rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def check_signatures(paths: list[str]) -> dict[str, str]:
    """Authenticode status per path (Valid, NotSigned, HashMismatch, FileMissing...)."""
    if not paths:
        return {}
    quoted = ",".join("'" + path.replace("'", "''") + "'" for path in paths)
    data = run_powershell(
        f"@({quoted}) | ForEach-Object {{ $p = $_; if (Test-Path -LiteralPath $p) {{ "
        "[pscustomobject]@{ path = $p; status = [string](Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue).Status } } "
        "else { [pscustomobject]@{ path = $p; status = 'FileMissing' } } } | ConvertTo-Json -Compress",
        timeout=60,
    )
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) and not data.get("error") else [])
    return {str(row.get("path")): str(row.get("status")) for row in rows if isinstance(row, dict)}


class Classifier:
    """Turns raw snapshots into security events. Pure logic, no I/O except
    the injected ``signer``."""

    def __init__(self, signer: Callable[[list[str]], dict[str, str]] = check_signatures) -> None:
        self.signer = signer
        self.baselined = False
        self.seen_records: deque[str] = deque(maxlen=5000)
        self.record_set: set[str] = set()
        self.known_processes: set[tuple[Any, Any]] = set()
        self.known_ports: set[tuple[str, int]] = set()
        self.known_usb: set[str] = set()
        self.usb_info: dict[str, dict[str, Any]] = {}
        self.failed: dict[tuple[str, str, str], list[float]] = defaultdict(list)
        self.last_burst: dict[tuple[Any, ...], float] = {}

    def _new_record(self, row: dict[str, Any]) -> bool:
        key = f"{row.get('log')}:{row.get('record_id')}"
        if key in self.record_set:
            return False
        if len(self.seen_records) == self.seen_records.maxlen:
            self.record_set.discard(self.seen_records[0])
        self.seen_records.append(key)
        self.record_set.add(key)
        return True

    @staticmethod
    def _event(key: str, kind: str, severity: str, title: str, detail: str, when: float, data: dict[str, Any]) -> dict[str, Any]:
        return {"event_key": key[:128], "event_type": kind, "severity": severity, "title": title[:200],
                "detail": detail[:1000], "occurred_at": iso(when), "data": data}

    def process(self, snapshot: dict[str, Any], now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        events: list[dict[str, Any]] = []
        events += self._windows_events(_rows(snapshot.get("events")), now)
        processes = _rows(snapshot.get("processes"))
        events += self._processes(processes, now)
        events += self._ports(_rows(snapshot.get("ports")), processes, now)
        events += self._usb(_rows(snapshot.get("usb")), now)
        self.baselined = True
        if len(events) > MAX_EVENTS_PER_CYCLE:
            omitted = len(events) - MAX_EVENTS_PER_CYCLE + 1
            events = events[: MAX_EVENTS_PER_CYCLE - 1] + [self._event(
                f"omitted:{int(now)}", "events_omitted", "Info", f"{omitted} eventos mas en este intervalo",
                "Se omitieron para no saturar el panel; revisa el registro de eventos del equipo.", now, {"omitted": omitted},
            )]
        return events

    def _windows_events(self, rows: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for row in rows:
            if not self._new_record(row):
                continue
            event_id = int(row.get("event_id") or 0)
            when = parse_time(row.get("time_created"))
            key = f"{row.get('log')}:{row.get('record_id')}"
            if event_id == 4625:
                ip = (row.get("source_ip") or "").strip()
                ip = "" if ip in {"-", "::1", "127.0.0.1"} else ip
                self.failed[(str(row.get("target_user") or "?"), ip, str(row.get("logon_type") or ""))].append(when)
            elif event_id == 4720:
                events.append(self._event(key, "account_created", "Medio", f"Cuenta local creada: {row.get('target_user')}",
                                          f"Creada por {row.get('subject_user') or 'desconocido'}.", when, dict(row)))
            elif event_id == 4732 and str(row.get("group_sid") or "").endswith(ADMINS_SID_SUFFIX):
                events.append(self._event(key, "admin_group_change", "Alto", "Cuenta agregada al grupo Administradores",
                                          f"{row.get('member_sid')} agregado por {row.get('subject_user') or 'desconocido'}.", when, dict(row)))
            elif event_id == 4740:
                events.append(self._event(key, "account_locked", "Medio", f"Cuenta bloqueada: {row.get('target_user')}",
                                          f"Bloqueada por intentos fallidos desde {row.get('caller_computer') or 'origen desconocido'}.", when, dict(row)))
            elif event_id == 1102:
                events.append(self._event(key, "log_cleared", "Critico", "Registro de seguridad borrado",
                                          f"Borrado por {row.get('subject_user') or 'desconocido'}. Es una senal fuerte de intrusion.", when, dict(row)))
            elif event_id == 7045:
                image = str(row.get("image_path") or "")
                command = image.strip()
                executable = command[1:].split('"', 1)[0] if command.startswith('"') else command.split(" ", 1)[0]
                suspicious = user_writable(executable) or any(
                    token in command.lower() for token in ("powershell", "cmd.exe /c", "-enc", "mshta", "rundll32"))
                events.append(self._event(
                    key, "service_installed", "Alto" if suspicious else "Medio",
                    f"Servicio instalado: {row.get('service_name')}",
                    f"{image} (cuenta {row.get('account') or '?'})" + (" - ruta o comando sospechoso" if suspicious else ""),
                    when, dict(row)))
            elif row.get("log") == "Defender":
                message = str(row.get("message") or "")
                title, severity = {
                    1116: ("Defender detecto una amenaza", "Critico"),
                    1117: ("Defender actuo contra una amenaza", "Alto"),
                    1118: ("Defender no pudo eliminar una amenaza", "Alto"),
                    1119: ("Defender fallo al eliminar una amenaza", "Alto"),
                    5001: ("Proteccion en tiempo real de Defender desactivada", "Critico"),
                }.get(event_id, ("Evento de Defender", "Medio"))
                events.append(self._event(key, "defender_event", severity, title, message, when, {"event_id": event_id}))
        events += self._bursts(now)
        return events

    def _bursts(self, now: float) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for key in list(self.failed):
            self.failed[key] = [t for t in self.failed[key] if now - t <= BURST_WINDOW_SECONDS]
            count = len(self.failed[key])
            if not count:
                del self.failed[key]
                continue
            level = 20 if count >= 20 else 5 if count >= 5 else 0
            if not level or now - self.last_burst.get((key, level), 0) < BURST_COOLDOWN_SECONDS:
                continue
            self.last_burst[(key, level)] = now
            user, ip, logon = key
            source = ip or "el propio equipo"
            events.append(self._event(
                f"bruteforce:{user}:{ip}:{level}:{int(now // BURST_COOLDOWN_SECONDS)}", "logon_failure_burst",
                "Critico" if level == 20 else "Alto", f"Posible fuerza bruta contra '{user}'",
                f"{count} inicios de sesion fallidos en {BURST_WINDOW_SECONDS // 60} minutos desde {source} "
                f"(tipo: {LOGON_TYPES.get(logon, logon or 'desconocido')}).",
                now, {"user": user, "source_ip": ip, "logon_type": logon, "count": count},
            ))
        return events

    def _processes(self, processes: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        current = {(row.get("pid"), row.get("created")) for row in processes}
        fresh = [row for row in processes if (row.get("pid"), row.get("created")) not in self.known_processes]
        self.known_processes = current
        if not self.baselined:
            return []
        candidates = [row for row in fresh if row.get("path") and user_writable(row["path"])][:SIGNATURE_CHECKS_PER_CYCLE]
        if not candidates:
            return []
        statuses = self.signer(sorted({str(row["path"]) for row in candidates}))
        events = []
        for row in candidates:
            status = statuses.get(str(row["path"]), "Unknown")
            if status == "Valid":
                continue
            events.append(self._event(
                f"proc:{row.get('pid')}:{row.get('created')}", "process_unsigned_user_path", "Alto",
                f"Proceso sin firma iniciado: {row.get('name')}",
                f"{row.get('path')} (PID {row.get('pid')}, padre {row.get('ppid')}, firma: {status}). "
                "Los programas sin firma en carpetas de usuario son tipicos del malware.",
                now, {"name": row.get("name"), "path": row.get("path"), "pid": row.get("pid"), "signature": status},
            ))
        return events

    def _ports(self, ports: list[dict[str, Any]], processes: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        names = {row.get("pid"): row.get("name") for row in processes}
        current = {(str(row.get("address")), int(row.get("port") or 0)) for row in ports}
        fresh = current - self.known_ports
        self.known_ports = current
        if not self.baselined:
            return []
        owners = {(str(row.get("address")), int(row.get("port") or 0)): row.get("pid") for row in ports}
        events = []
        for address, port in sorted(fresh):
            if address not in ALL_INTERFACES or not port:
                continue  # loopback or invalid: not reachable from the network
            risky = port in RISKY_PORTS
            owner = names.get(owners.get((address, port)), "proceso desconocido")
            events.append(self._event(
                f"port:{address}:{port}:{int(now // 3600)}", "new_listening_port", "Alto" if risky else "Medio",
                f"Nuevo puerto abierto a la red: {port}" + (f" ({RISKY_PORTS[port]})" if risky else ""),
                f"{owner} empezo a escuchar en {address}:{port}.", now, {"port": port, "address": address, "process": owner},
            ))
        return events

    def _usb(self, drives: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
        # A card reader without media reports no size: only real storage counts,
        # so inserting an SD card later shows up as a new drive.
        drives = [row for row in drives if str(row.get("size") or "").isdigit() and int(row["size"]) > 0]
        by_id = {str(row.get("serial") or row.get("model") or "?"): row for row in drives}
        fresh = set(by_id) - self.known_usb
        gone = self.known_usb - set(by_id)
        self.known_usb = set(by_id)
        events = []
        for ident in sorted(fresh):
            row = by_id[ident]
            self.usb_info[ident] = row
            size = f", {round(int(row['size']) / 1e9)} GB" if str(row.get("size") or "").isdigit() else ""
            # Drives already plugged in when monitoring starts are reported too,
            # once per hour at most (the server drops repeated keys).
            key = f"usb:{ident}:{int(now // 600)}" if self.baselined else f"usb:{ident}:start:{int(now // 3600)}"
            events.append(self._event(
                key, "usb_connected", "Medio",
                "Almacenamiento USB conectado" if self.baselined else "Almacenamiento USB conectado (ya estaba conectado)",
                f"{row.get('model') or 'USB'}{size}, serie {row.get('serial') or 'desconocida'}.", now,
                {"model": row.get("model"), "serial": row.get("serial"), "size": row.get("size"),
                 "already_connected": not self.baselined},
            ))
        for ident in sorted(gone):
            row = self.usb_info.pop(ident, {})
            events.append(self._event(
                f"usb-off:{ident}:{int(now // 600)}", "usb_disconnected", "Info", "Almacenamiento USB desconectado",
                f"{row.get('model') or 'USB'}, serie {row.get('serial') or ident}.", now,
                {"model": row.get("model"), "serial": row.get("serial")},
            ))
        return events


def collect_snapshot(since: float) -> dict[str, Any] | None:
    data = run_powershell(SNAPSHOT_SCRIPT.replace("__SINCE__", iso(since)), timeout=90)
    if isinstance(data, dict) and not data.get("error"):
        return data
    LOGGER.warning("Instantanea de eventos no disponible: %s", str(data)[:200])
    return None


class EventMonitor:
    def __init__(
        self,
        config: dict[str, Any],
        send: Callable[[dict[str, Any], list[dict[str, Any]]], None],
        collect: Callable[[float], dict[str, Any] | None] = collect_snapshot,
        classifier: Classifier | None = None,
    ) -> None:
        self.config = config
        self.send = send
        self.collect = collect
        self.classifier = classifier or Classifier()
        self.pending: deque[dict[str, Any]] = deque(maxlen=PENDING_LIMIT)
        self.since = time.time() - 120

    def cycle(self) -> int:
        """One collection + delivery pass. Returns how many events were sent."""
        started = time.time()
        snapshot = self.collect(self.since)
        if snapshot is not None:
            # Overlap by 10 s so events written while collecting are not missed;
            # record ids make the overlap harmless.
            self.since = started - 10
            self.pending.extend(self.classifier.process(snapshot, started))
        sent = 0
        while self.pending:
            batch = [self.pending[index] for index in range(min(BATCH_SIZE, len(self.pending)))]
            try:
                self.send(self.config, batch)
            except Exception as exc:  # noqa: BLE001 - keep events for the next cycle
                LOGGER.warning("Eventos pendientes de envio (%s): %s", len(self.pending), type(exc).__name__)
                break
            for _ in batch:
                self.pending.popleft()
            sent += len(batch)
        return sent

    def run(self, stop: threading.Event) -> None:
        LOGGER.info("Monitoreo en tiempo real iniciado (cada %s s)", POLL_SECONDS)
        while not stop.is_set():
            if self.config.get("token") and self.config.get("device_id"):
                try:
                    self.cycle()
                except Exception:  # noqa: BLE001 - the monitor must never die
                    LOGGER.exception("Fallo el ciclo de monitoreo")
            stop.wait(POLL_SECONDS)


def post_events(config: dict[str, Any], events: list[dict[str, Any]]) -> None:
    from agent.windows_agent import request_json  # local import: avoids a cycle at module load

    request_json(
        "POST", f"{config['api_url'].rstrip('/')}/api/agent/events", config["token"],
        {"device_id": config["device_id"], "events": events},
    )
