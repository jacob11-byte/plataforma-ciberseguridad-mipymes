"""Ready-to-paste PowerShell fixes, built with the real values of each device.

Small businesses rarely have IT staff, so every finding that can be fixed from
the computer itself gets a command the owner can copy into an administrator
PowerShell window. Values coming from the device (account names, paths,
ports...) are quoted with ``ps_quote`` so they are always literal strings.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable

EVERYONE = "(([Security.Principal.SecurityIdentifier]'S-1-1-0').Translate([Security.Principal.NTAccount]).Value)"


def ps_quote(value: Any) -> str:
    """Single-quoted PowerShell literal: nothing inside is interpreted."""
    return "'" + str(value).replace("'", "''") + "'"


def _items(evidence: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [item for item in evidence.get(key) or [] if isinstance(item, dict)]


def _fix(command: str, *, admin: bool = True, restart: bool = False, warning: str | None = None) -> dict[str, Any]:
    return {"command": command, "admin": admin, "restart": restart, "warning": warning}


def _services(e: dict[str, Any]) -> dict[str, Any] | None:
    names = [item.get("name") for item in _items(e, "services") if item.get("name")]
    if not names:
        return None
    return _fix("; ".join(
        f"Stop-Service -Name {ps_quote(name)} -Force; Set-Service -Name {ps_quote(name)} -StartupType Disabled"
        for name in names
    ))


def _admins(e: dict[str, Any]) -> dict[str, Any] | None:
    accounts = [name for name in e.get("unauthorized_accounts") or [] if name]
    if not accounts:
        return None
    return _fix(
        "; ".join(f"Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member {ps_quote(name)}" for name in accounts),
        warning="No quites tu propia cuenta si es la única con permisos de administrador.",
    )


def _backup(e: dict[str, Any]) -> dict[str, Any]:
    target = (e.get("path") or "C:\\Backups").rstrip("\\") + "\\Documentos"
    return _fix(
        f"robocopy \"$env:USERPROFILE\\Documents\" {ps_quote(target)} /E /R:1 /W:1",
        admin=False,
        warning="Esto copia tus Documentos a la carpeta de respaldos. Lo ideal es que esa carpeta esté en un disco externo o en la nube.",
    )


def _no_password(e: dict[str, Any]) -> dict[str, Any] | None:
    accounts = [name for name in e.get("accounts") or [] if name]
    if not accounts:
        return None
    return _fix("; ".join(
        f"net user {ps_quote(name)} /passwordreq:yes; "
        f"Set-LocalUser -Name {ps_quote(name)} -Password (Read-Host -AsSecureString {ps_quote('Nueva contraseña para ' + str(name))})"
        for name in accounts
    ))


def _exclusions(e: dict[str, Any]) -> dict[str, Any] | None:
    option = {"carpeta": "-ExclusionPath", "proceso": "-ExclusionProcess", "extension": "-ExclusionExtension"}
    commands = [
        f"Remove-MpPreference {option[item['type']]} {ps_quote(item['value'])}"
        for item in _items(e, "exclusions") if item.get("type") in option and item.get("value")
    ]
    return _fix("; ".join(commands), warning="Quita solo las que nadie en la empresa reconozca.") if commands else None


def _autoruns(e: dict[str, Any]) -> dict[str, Any] | None:
    commands = []
    for item in _items(e, "entries"):
        path, location, name = item.get("path"), str(item.get("location") or ""), item.get("name")
        if not path:
            continue
        commands.append(f"Start-MpScan -ScanType CustomScan -ScanPath {ps_quote(path)}")
        if location.startswith(("HKLM:", "Registry::")) and name:
            commands.append(f"Remove-ItemProperty -Path {ps_quote(location)} -Name {ps_quote(name)}")
        else:
            commands.append(f"Remove-Item -LiteralPath {ps_quote(path)}")
    return _fix("; ".join(commands), warning="El comando primero revisa el archivo con el antivirus y luego quita el inicio automático. "
                "Úsalo solo si no reconoces el programa.") if commands else None


def _shares(e: dict[str, Any]) -> dict[str, Any] | None:
    names = [item.get("name") for item in _items(e, "shares") if item.get("name")]
    if not names:
        return None
    return _fix("; ".join(
        f"Revoke-SmbShareAccess -Name {ps_quote(name)} -AccountName {EVERYONE} -Force" for name in names
    ), warning="Después, da acceso solo a las personas que lo necesitan (clic derecho en la carpeta → Propiedades → Compartir).")


def _ports(e: dict[str, Any]) -> dict[str, Any] | None:
    ports = sorted({int(item["port"]) for item in _items(e, "exposed") if str(item.get("port", "")).isdigit()})
    if not ports:
        return None
    return _fix("; ".join(
        f"New-NetFirewallRule -DisplayName {ps_quote(f'CyberCheck: bloquear puerto {port}')} -Direction Inbound "
        f"-Protocol TCP -LocalPort {port} -Action Block" for port in ports
    ), warning="Bloquea las conexiones desde otras computadoras; el programa sigue funcionando dentro de esta.")


def _processes(e: dict[str, Any]) -> dict[str, Any] | None:
    paths = sorted({item.get("path") for item in _items(e, "processes") if item.get("path")})
    if not paths:
        return None
    return _fix("; ".join(
        f"Get-Process | Where-Object {{ $_.Path -eq {ps_quote(path)} }} | Stop-Process -Force; "
        f"Start-MpScan -ScanType CustomScan -ScanPath {ps_quote(path)}" for path in paths
    ), warning="Cierra el programa y lo revisa con el antivirus. Si el antivirus lo marca como amenaza, lo eliminará.")


def _brute_force(e: dict[str, Any]) -> dict[str, Any]:
    commands = []
    for item in _items(e, "top_sources"):
        try:
            address = ipaddress.ip_address(str(item.get("source_ip") or ""))
        except ValueError:
            continue
        if address.is_loopback:
            continue
        commands.append(
            f"New-NetFirewallRule -DisplayName {ps_quote(f'CyberCheck: bloquear {address}')} -Direction Inbound "
            f"-RemoteAddress {ps_quote(str(address))} -Action Block"
        )
    commands.append("net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15")
    return _fix("; ".join(commands), warning="Bloquea a quien intenta entrar y hace que la cuenta se bloquee tras 10 intentos fallidos. "
                "Además, cambia esa contraseña (Ctrl+Alt+Supr → Cambiar una contraseña).")


def _new_accounts(e: dict[str, Any]) -> dict[str, Any] | None:
    names = sorted({item.get("target_user") for item in _items(e, "accounts") if item.get("target_user")})
    if not names:
        return None
    return _fix("; ".join(f"Disable-LocalUser -Name {ps_quote(name)}" for name in names),
                warning="Úsalo solo si nadie reconoce la cuenta: la desactiva sin borrarla.")


def _admin_added(e: dict[str, Any]) -> dict[str, Any] | None:
    members = sorted({item.get("member_sid") for item in _items(e, "changes") if item.get("member_sid")})
    if not members:
        return None
    return _fix("; ".join(f"Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member {ps_quote(sid)}" for sid in members),
                warning="Úsalo solo si el cambio no fue autorizado.")


def _services_installed(e: dict[str, Any]) -> dict[str, Any] | None:
    names = sorted({item.get("service_name") for item in _items(e, "services") if item.get("service_name")})
    if not names:
        return None
    return _fix("; ".join(
        f"Get-Service -DisplayName {ps_quote(name)} | Stop-Service -Force -PassThru | Set-Service -StartupType Disabled"
        for name in names
    ), warning="Úsalo solo si no reconoces ese programa.")


def _software(e: dict[str, Any]) -> dict[str, Any] | None:
    commands = []
    for item in _items(e, "programs"):
        winget = {"WinRAR": "RARLab.WinRAR", "7-Zip": "7zip.7zip", "PuTTY": "PuTTY.PuTTY",
                  "Notepad++": "Notepad++.Notepad++"}.get(str(item.get("product")))
        if item.get("eol"):
            commands.append(f"winget uninstall --name {ps_quote(item.get('product'))}")
        elif winget:
            commands.append(f"winget upgrade --id {winget} --accept-source-agreements --accept-package-agreements")
    return _fix("; ".join(commands), admin=False) if commands else None


FIXES: dict[str, Callable[[dict[str, Any]], dict[str, Any] | None]] = {
    "FIREWALL_PUBLIC_DISABLED": lambda e: _fix("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"),
    "RDP_EXPOSED": lambda e: _fix(
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
        warning="Apaga el Escritorio remoto. No lo uses si alguien se conecta a esta computadora a distancia."),
    "RISKY_SERVICE_ENABLED": _services,
    "UNAUTHORIZED_LOCAL_ADMIN": _admins,
    "UPDATES_PENDING": lambda e: _fix("Start-Process 'ms-settings:windowsupdate-action'", admin=False,
                                      warning="Abre Windows Update y empieza a buscar. Instala todo y reinicia cuando te lo pida."),
    "ANTIVIRUS_DISABLED": lambda e: _fix(
        "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false; "
        "Start-Process 'windowsdefender://threatsettings'",
        warning="Si la «Protección contra alteraciones» está activa, Windows puede ignorar el comando: en la ventana que se "
                "abre, enciende tú mismo «Protección en tiempo real»."),
    "ANTIVIRUS_SIGNATURES_OLD": lambda e: _fix("Update-MpSignature"),
    "ANTIVIRUS_SCAN_OLD": lambda e: _fix("Start-MpScan -ScanType QuickScan"),
    "ANTIVIRUS_ACTIVE_THREATS": lambda e: _fix("Remove-MpThreat; Start-MpScan -ScanType FullScan",
                                               warning="El examen completo puede tardar más de una hora; puedes seguir usando la computadora."),
    "DEVICE_WITH_ERROR": lambda e: _fix("pnputil /scan-devices; Start-Process devmgmt.msc",
                                        warning="Vuelve a detectar los aparatos y abre el Administrador de dispositivos para revisar el que tiene un signo amarillo."),
    "UNSIGNED_DEVICE_DRIVER": lambda e: _fix("Start-Process devmgmt.msc", admin=False,
                                             warning="Abre el Administrador de dispositivos: clic derecho en el aparato → Actualizar controlador."),
    "BACKUP_OLD_OR_MISSING": _backup,
    "UAC_DISABLED": lambda e: _fix(
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        restart=True),
    "SMB1_ENABLED": lambda e: _fix("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart", restart=True,
                                   warning="Si tienes un equipo muy viejo (impresora o disco de red de hace más de 10 años) que deje de "
                                           "funcionar, actualízalo; no vuelvas a encender esta función."),
    "RDP_NLA_DISABLED": lambda e: _fix(
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"),
    "BITLOCKER_OFF": lambda e: _fix("Start-Process control.exe -ArgumentList '/name Microsoft.BitLockerDriveEncryption'",
                                    warning="Abre BitLocker: pulsa «Activar BitLocker» en el disco C: y guarda la clave de recuperación "
                                            "en tu cuenta Microsoft o impresa, fuera de la computadora."),
    "SECURE_BOOT_OFF": lambda e: _fix("shutdown /r /fw /t 0", restart=True,
                                      warning="Guarda tu trabajo: la computadora se reinicia directo en su configuración interna. Busca "
                                              "«Secure Boot» (pestaña Boot o Security), ponlo en «Enabled» y guarda con F10."),
    "GUEST_ACCOUNT_ENABLED": lambda e: _fix("Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser"),
    "BUILTIN_ADMIN_ENABLED": lambda e: _fix("Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser",
                                            warning="No lo uses si «Administrador» es la cuenta con la que entras a la computadora."),
    "ACCOUNT_NO_PASSWORD_REQUIRED": _no_password,
    "PASSWORD_POLICY_WEAK": lambda e: _fix("net accounts /minpwlen:12 /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15",
                                           warning="Las contraseñas actuales siguen funcionando; la regla aplica la próxima vez que se cambien."),
    "WDIGEST_PLAINTEXT": lambda e: _fix(
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0",
        restart=True, warning="Después de reiniciar, cambia las contraseñas de quienes usaron esta computadora."),
    "NTLMV1_ALLOWED": lambda e: _fix(
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5",
        restart=True, warning="Si un equipo de red muy antiguo deja de conectarse, actualízalo."),
    "LLMNR_ENABLED": lambda e: _fix(
        "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; "
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0"),
    "DEFENDER_EXCLUSIONS": _exclusions,
    "AUTORUN_UNSIGNED_USER_PATH": _autoruns,
    "SHARE_OPEN_TO_EVERYONE": _shares,
    "RISKY_PORT_LISTENING": _ports,
    "PROCESS_UNSIGNED_USER_PATH": _processes,
    "OS_END_OF_SUPPORT": lambda e: _fix("Start-Process 'ms-settings:windowsupdate'", admin=False,
                                        warning="Si Windows Update ofrece «Actualizar a Windows 11», acéptalo (es gratis). Si no aparece, "
                                                "tu computadora no lo admite y conviene planear cambiarla."),
    "BRUTE_FORCE_LOGON": _brute_force,
    "NEW_LOCAL_ACCOUNT": _new_accounts,
    "ADMIN_GROUP_MEMBER_ADDED": _admin_added,
    "SECURITY_LOG_CLEARED": lambda e: _fix("Start-MpScan -ScanType FullScan",
                                           warning="Revisa toda la computadora con el antivirus y cambia la contraseña de la cuenta que borró el historial."),
    "SUSPICIOUS_SERVICE_INSTALLED": _services_installed,
    "VULNERABLE_SOFTWARE": _software,
    "EXPLOITED_VULN_UNPATCHED": lambda e: _fix("Start-Process 'ms-settings:windowsupdate-action'", admin=False,
                                               warning="Instala todo lo que aparezca y reinicia la computadora hoy mismo."),
}


def fix_for(rule_id: str, evidence: dict[str, Any] | None) -> dict[str, Any] | None:
    builder = FIXES.get(rule_id)
    if builder is None:
        return None
    try:
        fix = builder(evidence or {})
    except (TypeError, ValueError, KeyError, AttributeError):
        return None
    return fix if fix and fix.get("command") else None
