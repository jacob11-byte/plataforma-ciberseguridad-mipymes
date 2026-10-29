from __future__ import annotations

import argparse
import ctypes
import os
import socket
import sys
import threading
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.outbox import Outbox
from agent.public_status import read_public_status, utc_now, write_public_status
from agent.windows_agent import (
    AGENT_VERSION,
    AgentAlreadyRunning,
    AgentInstanceLock,
    configure_logging,
    ensure_registered,
    load_agent_config,
    log_failure,
    poll_once,
    redact_error,
)


SERVICE_NAME = "CyberCheckAgent"
SERVICE_DISPLAY_NAME = "CyberCheck MIPYME Agent"


def service_status(config: dict[str, Any], **updates: Any) -> dict[str, Any]:
    previous = read_public_status()
    status = {
        "agent_version": AGENT_VERSION,
        "connectivity": previous.get("connectivity", "unknown"),
        "dashboard_url": config.get("api_url"),
        "device_name": socket.gethostname(),
        "last_attempt": previous.get("last_attempt"),
        "last_error": previous.get("last_error"),
        "last_success": previous.get("last_success"),
        "outbox_dead": previous.get("outbox_dead", 0),
        "outbox_pending": previous.get("outbox_pending", 0),
        "service_state": previous.get("service_state", "starting"),
    }
    status.update(updates)
    try:
        stats = Outbox().stats()
        status["outbox_pending"] = stats["pending"]
        status["outbox_dead"] = stats["dead"]
    except OSError:
        pass
    return status


def run_agent_cycle(config: dict[str, Any], max_tasks: int = 10) -> dict[str, Any]:
    attempted_at = utc_now()
    try:
        ensure_registered(config, Path(config["_config_path"]))
        poll_once(config, max_tasks=max_tasks)
    except Exception as exc:
        log_failure("Ciclo del servicio sin conexion", exc, config)
        status = service_status(
            config,
            service_state="running",
            connectivity="offline",
            last_attempt=attempted_at,
            last_error=f"{type(exc).__name__}: {redact_error(exc, config)}",
        )
        write_public_status(status)
        return status
    status = service_status(
        config,
        service_state="running",
        connectivity="online",
        last_attempt=attempted_at,
        last_success=utc_now(),
        last_error=None,
    )
    write_public_status(status)
    return status


def run_service_worker(
    config_path: Path,
    stop_event: threading.Event,
    *,
    interval_seconds: int = 300,
    max_tasks: int = 10,
    once: bool = False,
) -> int:
    configure_logging()
    lock = AgentInstanceLock(config_path)
    config: dict[str, Any] = {"api_url": None}
    try:
        lock.acquire()
        config = load_agent_config(config_path)
        config["_config_path"] = str(config_path)
        write_public_status(service_status(config, service_state="starting", last_error=None))
        while not stop_event.is_set():
            run_agent_cycle(config, max_tasks=max_tasks)
            if once or stop_event.wait(interval_seconds):
                break
        current = service_status(config, service_state="stopped")
        write_public_status(current)
        return 0
    except AgentAlreadyRunning as exc:
        log_failure("El servicio no puede iniciar", exc, config)
        write_public_status(service_status(config, service_state="blocked", last_error=str(exc)))
        return 2
    except Exception as exc:
        log_failure("Fallo fatal del servicio", exc, config)
        write_public_status(
            service_status(
                config,
                service_state="failed",
                connectivity="unknown",
                last_error=f"{type(exc).__name__}: {redact_error(exc, config)}",
            )
        )
        return 1
    finally:
        lock.release()


def run_windows_service(args: argparse.Namespace) -> int:
    if os.name != "nt":
        raise RuntimeError("El host de servicio solo funciona en Windows")

    from ctypes import wintypes

    service_win32_own_process = 0x00000010
    service_stopped = 0x00000001
    service_start_pending = 0x00000002
    service_stop_pending = 0x00000003
    service_running = 0x00000004
    service_accept_stop = 0x00000001
    service_accept_shutdown = 0x00000004
    service_control_stop = 0x00000001
    service_control_interrogate = 0x00000004
    service_control_shutdown = 0x00000005
    no_error = 0
    error_service_specific = 1066

    class ServiceStatus(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    handler_type = ctypes.WINFUNCTYPE(
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID
    )
    service_main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

    class ServiceTableEntry(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", service_main_type)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
        wintypes.LPCWSTR,
        handler_type,
        wintypes.LPVOID,
    ]
    advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(ServiceStatus)]
    advapi32.SetServiceStatus.restype = wintypes.BOOL
    advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(ServiceTableEntry)]
    advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL

    stop_event = threading.Event()
    status_handle: wintypes.HANDLE | None = None
    current_status = ServiceStatus()

    def set_status(state: int, exit_code: int = 0, wait_hint: int = 0) -> None:
        if not status_handle:
            return
        current_status.dwServiceType = service_win32_own_process
        current_status.dwCurrentState = state
        current_status.dwControlsAccepted = (
            0 if state in {service_start_pending, service_stop_pending, service_stopped}
            else service_accept_stop | service_accept_shutdown
        )
        # A non-zero worker code is reported as a service-specific error so the
        # SCM failure actions (restart) apply and Event Viewer shows the code.
        current_status.dwWin32ExitCode = error_service_specific if exit_code else 0
        current_status.dwServiceSpecificExitCode = exit_code
        current_status.dwCheckPoint = 0
        current_status.dwWaitHint = wait_hint
        advapi32.SetServiceStatus(status_handle, ctypes.byref(current_status))

    @handler_type
    def control_handler(control: int, _event_type: int, _event_data: Any, _context: Any) -> int:
        if control in {service_control_stop, service_control_shutdown}:
            set_status(service_stop_pending, wait_hint=30_000)
            stop_event.set()
        elif control == service_control_interrogate:
            set_status(current_status.dwCurrentState)
        return no_error

    @service_main_type
    def service_main(_argc: int, _argv: Any) -> None:
        nonlocal status_handle
        status_handle = advapi32.RegisterServiceCtrlHandlerExW(args.service_name, control_handler, None)
        if not status_handle:
            return
        set_status(service_start_pending, wait_hint=15_000)
        result: list[int] = []

        def worker() -> None:
            result.append(
                run_service_worker(
                    Path(args.config),
                    stop_event,
                    interval_seconds=args.interval,
                    max_tasks=args.max_tasks,
                )
            )

        thread = threading.Thread(target=worker, name="CyberCheckWorker", daemon=True)
        thread.start()
        set_status(service_running)
        while thread.is_alive() and not stop_event.wait(1):
            pass
        if stop_event.is_set():
            thread.join(timeout=25)
        exit_code = result[0] if result else 0
        set_status(service_stopped, exit_code=exit_code)

    table = (ServiceTableEntry * 2)()
    table[0] = ServiceTableEntry(args.service_name, service_main)
    if not advapi32.StartServiceCtrlDispatcherW(table):
        error = ctypes.get_last_error()
        raise OSError(error, "StartServiceCtrlDispatcherW fallo")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=SERVICE_DISPLAY_NAME)
    parser.add_argument(
        "--config",
        default=str(Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "CyberCheck" / "agent_config.json"),
    )
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--max-tasks", type=int, default=10)
    parser.add_argument("--service-name", default=SERVICE_NAME)
    parser.add_argument("--console", action="store_true", help="Ejecutar fuera del Service Control Manager")
    parser.add_argument("--once", action="store_true", help="Ejecutar un ciclo en modo consola")
    args = parser.parse_args()
    if args.interval < 5 or args.max_tasks < 1:
        parser.error("interval debe ser >= 5 y max-tasks debe ser >= 1")
    if args.console:
        stop_event = threading.Event()
        try:
            return run_service_worker(
                Path(args.config),
                stop_event,
                interval_seconds=args.interval,
                max_tasks=args.max_tasks,
                once=args.once,
            )
        except KeyboardInterrupt:
            stop_event.set()
            return 0
    return run_windows_service(args)


if __name__ == "__main__":
    raise SystemExit(main())
