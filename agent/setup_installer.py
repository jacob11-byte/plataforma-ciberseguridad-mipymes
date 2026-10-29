"""CyberCheck setup: one double-click installs, upgrades or removes the agent.

Built with ``--uac-admin`` so Windows asks for elevation once. The installer
bundles the three agent executables and an enrollment file (API URL and
registration code, never a device token). It also accepts ``/quiet`` for
mass deployment (GPO, Intune, RMM) and ``/uninstall [/purge]``.
"""
from __future__ import annotations

import ctypes
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.windows_agent import AGENT_VERSION, validate_agent_config

SERVICE_NAME = "CyberCheckAgent"
SERVICE_DISPLAY_NAME = "CyberCheck MIPYME Agent"
PRODUCT_NAME = "CyberCheck MIPYME Agent"
PUBLISHER = "CyberCheck MIPYME"
COMPONENTS = ("CyberCheckAgent.exe", "CyberCheckService.exe", "CyberCheckTray.exe")
LEGACY_TASKS = ("CyberCheck MIPYME Agent", "CyberCheck MIPYME Agent User")
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
UNINSTALL_KEY = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{SERVICE_NAME}"
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"
SERVICE_INTERVAL_SECONDS = 300
SID_SYSTEM = "*S-1-5-18"
SID_ADMINS = "*S-1-5-32-544"
SID_USERS = "*S-1-5-32-545"
CREATE_NO_WINDOW = 0x08000000

LOGGER = logging.getLogger("cybercheck.setup")


class SetupError(RuntimeError):
    pass


def install_root() -> Path:
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CyberCheck" / "Agent"


def data_root() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "CyberCheck"


def payload_root() -> Path:
    bundle = getattr(sys, "_MEIPASS", None)
    return Path(bundle) / "payload" if bundle else Path(__file__).resolve().parent.parent / "dist"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    LOGGER.info("%s -> %s", " ".join(command), result.returncode)
    if check and result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()[:300]
        raise SetupError(f"Fallo '{command[0]} {command[1] if len(command) > 1 else ''}': {detail}")
    return result


# --- Enrollment and configuration -------------------------------------------------

ENROLLMENT_NAME = re.compile(r"CyberCheckSetup_([0-9a-f]{32})", re.IGNORECASE)


def enrollment_token_from_name(name: str) -> str | None:
    """Token the panel embeds in the download name: CyberCheckSetup_<token>.exe.

    Browsers may append " (1)" to repeated downloads; the pattern ignores it.
    """
    match = ENROLLMENT_NAME.search(name)
    return match.group(1).lower() if match else None


def load_enrollment(path: Path, token: str | None = None) -> dict[str, Any]:
    try:
        enrollment = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError("El instalador no contiene una configuracion de registro valida") from exc
    if not isinstance(enrollment, dict):
        raise SetupError("La configuracion de registro debe ser un objeto JSON")
    if enrollment.get("token") or enrollment.get("device_id"):
        # A device token baked into an installer would make every computer
        # impersonate the same device.
        raise SetupError("La configuracion de registro no debe contener device_id ni token")
    if token:
        enrollment["registration_code"] = token
    if not enrollment.get("registration_code"):
        raise SetupError(
            "Este instalador no esta vinculado a ninguna cuenta. Descargalo desde el panel con el boton "
            "'Agregar computadora' y no cambies el nombre del archivo."
        )
    try:
        validate_agent_config(enrollment)
    except ValueError as exc:
        raise SetupError(f"Configuracion de registro invalida: {exc}") from exc
    return enrollment


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def credentials_rejected(config: dict[str, Any], timeout: float = 90) -> bool:
    """True only when the API explicitly refuses the stored device token."""
    body = json.dumps({"device_id": config["device_id"], "agent_version": AGENT_VERSION}).encode("utf-8")
    request = urllib.request.Request(
        f"{config['api_url'].rstrip('/')}/api/agent/heartbeat", data=body, method="POST"
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {config['token']}")
    request.add_header("User-Agent", f"CyberCheck-Setup/{AGENT_VERSION}")
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            return False
    except urllib.error.HTTPError as exc:
        return exc.code in {401, 403}
    except (urllib.error.URLError, TimeoutError, OSError):
        # Offline during setup: keep the existing identity rather than
        # creating a duplicate device.
        return False


def resolve_config(
    existing: dict[str, Any] | None,
    enrollment: dict[str, Any],
    rejected: Callable[[dict[str, Any]], bool] = credentials_rejected,
) -> tuple[dict[str, Any], str]:
    """Decide which configuration the service should run with.

    Returns the config and a reason: ``kept`` keeps an enrolled identity on
    upgrade, ``enroll`` writes the enrollment so the service registers.
    """
    enrolled = (
        existing is not None
        and existing.get("device_id")
        and existing.get("token")
        and str(existing.get("api_url", "")).rstrip("/") == str(enrollment["api_url"]).rstrip("/")
    )
    if enrolled:
        try:
            validate_agent_config(existing)
        except ValueError:
            enrolled = False
    if enrolled and not rejected(existing):
        return existing, "kept"
    fresh = {key: value for key, value in enrollment.items() if not key.startswith("_")}
    return fresh, "enroll"


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


# --- Windows plumbing -------------------------------------------------------------

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def message(text: str, title: str = PRODUCT_NAME, flags: int = 0x40) -> int:
    return ctypes.windll.user32.MessageBoxW(None, text, title, flags | 0x10000)


def service_exists() -> bool:
    return run(["sc.exe", "query", SERVICE_NAME], check=False).returncode != 1060


def wait_service_state(state: str, timeout: float = 45) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = run(["sc.exe", "query", SERVICE_NAME], check=False).stdout
        if state in output:
            return True
        time.sleep(1)
    return False


def stop_components() -> None:
    if service_exists():
        run(["sc.exe", "stop", SERVICE_NAME], check=False)
        wait_service_state("STOPPED", timeout=40)
    for image in COMPONENTS:
        run(["taskkill.exe", "/F", "/IM", image], check=False)
    for task in LEGACY_TASKS:
        run(["schtasks.exe", "/End", "/TN", task], check=False)
        run(["schtasks.exe", "/Delete", "/TN", task, "/F"], check=False)


def reclaim(path: Path) -> None:
    """Make Administrators owner and reset ACLs left by earlier installs.

    Files created by previous agent versions can carry DACLs that deny even
    elevated administrators; ownership lets us rewrite them.
    """
    if path.exists():
        run(["icacls.exe", str(path), "/setowner", SID_ADMINS, "/T", "/C", "/Q"], check=False)
        run(["icacls.exe", str(path), "/reset", "/T", "/C", "/Q"], check=False)


def secure_directories(program_dir: Path, data_dir: Path) -> None:
    public_dir = data_dir / "public"
    public_dir.mkdir(parents=True, exist_ok=True)
    run(["icacls.exe", str(program_dir), "/inheritance:r", "/grant:r",
         f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F", f"{SID_USERS}:(OI)(CI)RX", "/T", "/C", "/Q"])
    # Config, token, offline queue and logs: SYSTEM and Administrators only.
    run(["icacls.exe", str(data_dir), "/inheritance:r", "/grant:r",
         f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F", "/T", "/C", "/Q"])
    # Users may traverse the root and read only the sanitized status.
    run(["icacls.exe", str(data_dir), "/grant", f"{SID_USERS}:(RX)", "/C", "/Q"])
    run(["icacls.exe", str(public_dir), "/inheritance:r", "/grant:r",
         f"{SID_SYSTEM}:(OI)(CI)F", f"{SID_ADMINS}:(OI)(CI)F", f"{SID_USERS}:(OI)(CI)RX", "/T", "/C", "/Q"])


def copy_components(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for name in COMPONENTS:
        origin = source / name
        if not origin.is_file():
            raise SetupError(f"Falta el componente {name} en el instalador")
        shutil.copy2(origin, target / name)
    if getattr(sys, "frozen", False):
        current = Path(sys.executable).resolve()
        installed = target / "CyberCheckSetup.exe"
        if current != installed.resolve():
            shutil.copy2(current, installed)


def service_command(program_dir: Path, config_path: Path) -> str:
    return (
        f'"{program_dir / "CyberCheckService.exe"}" --config "{config_path}" '
        f'--interval {SERVICE_INTERVAL_SECONDS} --max-tasks 10 --service-name "{SERVICE_NAME}"'
    )


def configure_service(program_dir: Path, config_path: Path) -> None:
    import winreg

    if not service_exists():
        run(["sc.exe", "create", SERVICE_NAME,
             "binPath=", str(program_dir / "CyberCheckService.exe"),
             "start=", "delayed-auto", "DisplayName=", SERVICE_DISPLAY_NAME])
    else:
        run(["sc.exe", "config", SERVICE_NAME, "start=", "delayed-auto"])
    # sc.exe mangles nested quotes, so the full command line goes straight to
    # the SCM registry key.
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ImagePath", 0, winreg.REG_EXPAND_SZ, service_command(program_dir, config_path))
    run(["sc.exe", "description", SERVICE_NAME, "Agente de postura de seguridad CyberCheck MIPYME"])
    run(["sc.exe", "failure", SERVICE_NAME, "reset=", "86400",
         "actions=", "restart/60000/restart/60000/restart/300000"])
    run(["sc.exe", "failureflag", SERVICE_NAME, "1"])


def register_shell_entries(program_dir: Path, data_dir: Path) -> None:
    import winreg

    tray = program_dir / "CyberCheckTray.exe"
    setup = program_dir / "CyberCheckSetup.exe"
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "CyberCheckTray", 0, winreg.REG_SZ, f'"{tray}" --data-root "{data_dir}"')
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, winreg.KEY_SET_VALUE) as key:
        values = {
            "DisplayName": PRODUCT_NAME,
            "DisplayVersion": AGENT_VERSION,
            "Publisher": PUBLISHER,
            "InstallLocation": str(program_dir),
            "DisplayIcon": str(tray),
            "UninstallString": f'"{setup}" /uninstall',
            "QuietUninstallString": f'"{setup}" /uninstall /quiet',
            "InstallDate": datetime.now().strftime("%Y%m%d"),
        }
        for name, value in values.items():
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def remove_shell_entries() -> None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "CyberCheckTray")
    except OSError:
        pass
    try:
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL_KEY)
    except OSError:
        pass


def launch_tray_for_current_user(program_dir: Path) -> None:
    # explorer.exe starts the program un-elevated in the interactive session;
    # the tray reads ProgramData\CyberCheck by default.
    try:
        subprocess.Popen(["explorer.exe", str(program_dir / "CyberCheckTray.exe")],
                         creationflags=CREATE_NO_WINDOW)
    except OSError:
        LOGGER.warning("No se pudo iniciar el icono de bandeja; aparecera al iniciar sesion")


# --- Install / uninstall ----------------------------------------------------------

def install(payload: Path) -> str:
    program_dir, data_dir = install_root(), data_root()
    enrollment = load_enrollment(
        payload / "enrollment.json", enrollment_token_from_name(Path(sys.executable).name)
    )
    LOGGER.info("Instalando %s %s", PRODUCT_NAME, AGENT_VERSION)

    stop_components()
    reclaim(data_dir)
    reclaim(program_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    config_path = data_dir / "agent_config.json"
    config, reason = resolve_config(read_json(config_path), enrollment)
    write_json_atomic(config_path, config)
    LOGGER.info("Configuracion: %s", reason)

    copy_components(payload, program_dir)
    secure_directories(program_dir, data_dir)
    configure_service(program_dir, config_path)
    register_shell_entries(program_dir, data_dir)

    run(["sc.exe", "start", SERVICE_NAME], check=False)
    if not wait_service_state("RUNNING", timeout=45):
        raise SetupError("El servicio se instalo pero no llego a ejecutarse; revisa el Visor de eventos")
    return reason


def schedule_directory_removal(path: Path) -> None:
    # The running uninstaller lives inside the directory; a detached helper
    # deletes it once this process exits.
    script = f'ping 127.0.0.1 -n 4 > nul & rmdir /s /q "{path}"'
    subprocess.Popen(["cmd.exe", "/c", script], creationflags=CREATE_NO_WINDOW, close_fds=True)


def uninstall(purge: bool) -> None:
    program_dir, data_dir = install_root(), data_root()
    stop_components()
    if service_exists():
        run(["sc.exe", "delete", SERVICE_NAME])
    remove_shell_entries()
    running_inside = Path(sys.executable).resolve().parent == program_dir.resolve()
    if program_dir.exists():
        if running_inside:
            schedule_directory_removal(program_dir)
        else:
            shutil.rmtree(program_dir, ignore_errors=True)
    if purge and data_dir.exists():
        reclaim(data_dir)
        shutil.rmtree(data_dir, ignore_errors=True)


def configure_setup_logging() -> Path:
    log_path = data_root() / "setup.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.FileHandler(log_path, encoding="utf-8")
    except OSError:
        log_path = Path(tempfile.gettempdir()) / "CyberCheckSetup.log"
        handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.info("--- %s ---", datetime.now(timezone.utc).isoformat())
    return log_path


def parse_flags(argv: list[str]) -> set[str]:
    return {arg.lstrip("/-").lower() for arg in argv}


def main(argv: list[str] | None = None) -> int:
    flags = parse_flags(sys.argv[1:] if argv is None else argv)
    quiet = bool(flags & {"quiet", "q", "silent", "s"})
    if os.name != "nt":
        return 1
    if not is_admin():
        if not quiet:
            message("Ejecuta el instalador como administrador.", flags=0x10)
        return 5
    log_path = configure_setup_logging()

    if "uninstall" in flags:
        if not quiet and message(
            "Se eliminara el agente CyberCheck de este equipo. Continuar?", flags=0x24
        ) != 6:
            return 1
        try:
            uninstall(purge="purge" in flags)
        except Exception as exc:
            LOGGER.exception("Desinstalacion fallida")
            if not quiet:
                message(f"No se pudo desinstalar: {exc}\n\nRegistro: {log_path}", flags=0x10)
            return 1
        if not quiet:
            message("CyberCheck se desinstalo correctamente.")
        return 0

    if not quiet and message(
        f"Se instalara {PRODUCT_NAME} {AGENT_VERSION} como servicio de Windows.\n\n"
        "Revisara la seguridad de este equipo de forma automatica y enviara la evidencia "
        "al panel de tu organizacion. Continuar?",
        flags=0x24,
    ) != 6:
        return 1
    try:
        reason = install(payload_root())
    except Exception as exc:
        LOGGER.exception("Instalacion fallida")
        if not quiet:
            message(f"No se pudo completar la instalacion:\n{exc}\n\nRegistro: {log_path}", flags=0x10)
        return 1
    if not quiet:
        launch_tray_for_current_user(install_root())
        detail = (
            "Se conservo el registro existente de este equipo."
            if reason == "kept"
            else "El equipo se registrara en el panel en el primer minuto."
        )
        message(
            "CyberCheck quedo instalado y funcionando.\n\n"
            f"{detail}\nEl icono junto al reloj muestra el estado de conexion.\n\n"
            "Para quitarlo: Configuracion > Aplicaciones > CyberCheck MIPYME Agent."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
