from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    control: str
    title: str
    severity: str
    triggered: bool
    evidence: dict[str, Any]
    recommendation: str
    closure_criteria: str


RISKY_SERVICES = {
    "TermService": "Servicios de Escritorio remoto habilitados",
    "RemoteRegistry": "Registro remoto habilitado",
    "WinRM": "Administracion remota WinRM habilitada",
}


def _bool(value: Any) -> bool:
    return str(value).lower() in {"true", "1", "yes", "enabled", "on"}


def _admin_name(value: Any) -> str:
    text = str(value)
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    return text.strip().lower()


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _available(value: Any) -> bool:
    """A failed or unsupported collection cannot prove a control was corrected."""
    if value is None:
        return False
    if isinstance(value, dict):
        if value.get("success") is False or value.get("error"):
            return False
        if value.get("status") in {"error", "unavailable", "not_supported", "not_configured"}:
            return False
    return True


def _port_number(item: Any) -> int | None:
    value = item.get("port") if isinstance(item, dict) else item
    return _int_or_none(value)


def evaluate_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    results: list[RuleResult] = []
    if "firewall" in evidence:
        firewall = evidence.get("firewall")
        if isinstance(firewall, dict) and _available(firewall) and firewall.get("public") is not None:
            public_enabled = _bool(firewall["public"])
            results.append(
                RuleResult(
                    rule_id="FIREWALL_PUBLIC_DISABLED",
                    control="firewall",
                    title="Cortafuegos publico desactivado",
                    severity="Alto",
                    triggered=not public_enabled,
                    evidence={"public": firewall.get("public")},
                    recommendation="Activar el perfil publico del cortafuegos y verificar nuevamente.",
                    closure_criteria="El perfil publico aparece activo en una nueva evidencia.",
                )
            )
    else:
        firewall = {}

    raw_ports = evidence.get("listening_ports")
    raw_services = evidence.get("services")
    ports = raw_ports if isinstance(raw_ports, list) else []
    services = raw_services if isinstance(raw_services, list) else []
    ports_available = isinstance(raw_ports, list)
    services_available = isinstance(raw_services, list)
    port_3389 = any(_port_number(item) == 3389 for item in ports)
    term_service = any(
        str(item.get("name", "")).lower() == "termservice" and _bool(item.get("running", False))
        for item in services
        if isinstance(item, dict)
    )
    # A negative result from only one source cannot disprove a prior positive
    # result from the other source.
    if port_3389 or term_service or (ports_available and services_available):
        results.append(
            RuleResult(
                rule_id="RDP_EXPOSED",
                control="ports",
                title="RDP activo o puerto 3389 en escucha local",
                severity="Alto",
                triggered=port_3389 or term_service,
                evidence={"port_3389_listening": port_3389, "termservice_running": term_service},
                recommendation="Restringir RDP, detenerlo si no se usa o bloquear el puerto segun necesidad.",
                closure_criteria="El servicio o la exposicion deja de cumplir la condicion.",
            )
        )

    risky = [
        item
        for item in services
        if isinstance(item, dict)
        and item.get("name") in RISKY_SERVICES
        and item.get("name") != "TermService"
        and _bool(item.get("running", False))
    ]
    if services_available and all(isinstance(item, dict) and item.get("running") is not None for item in services):
        results.append(
            RuleResult(
                rule_id="RISKY_SERVICE_ENABLED",
                control="services",
                title="Servicio remoto de riesgo habilitado",
                severity="Alto",
                triggered=bool(risky),
                evidence={"services": risky},
                recommendation="Deshabilitar servicios remotos que no sean necesarios para la operacion.",
                closure_criteria="Los servicios definidos como riesgo aparecen detenidos o deshabilitados.",
            )
        )

    admins = evidence.get("local_administrators", evidence.get("local_admins"))
    authorized_admins = evidence.get("authorized_local_admins")
    if isinstance(admins, list) and isinstance(authorized_admins, list):
        authorized_names = {_admin_name(name) for name in authorized_admins}
        unauthorized = [name for name in admins if _admin_name(name) not in authorized_names]
        results.append(
            RuleResult(
                rule_id="UNAUTHORIZED_LOCAL_ADMIN",
                control="administrators",
                title="Cuenta no autorizada como administrador local",
                severity="Alto",
                triggered=bool(unauthorized),
                evidence={"unauthorized_accounts": unauthorized},
                recommendation="Retirar del grupo Administradores las cuentas que no esten autorizadas.",
                closure_criteria="La cuenta ya no aparece dentro del grupo Administradores.",
            )
        )

    updates = evidence.get("updates")
    if isinstance(updates, dict) and _available(updates):
        pending_count = _int_or_none(updates.get("pending_count"))
        reboot_pending = updates.get("reboot_pending")
        if pending_count is not None and reboot_pending is not None:
            triggered_updates = pending_count > 0 or _bool(reboot_pending)
        else:
            triggered_updates = None
    else:
        triggered_updates = None
        pending_count = None
    if triggered_updates is not None:
        results.append(
            RuleResult(
                rule_id="UPDATES_PENDING",
                control="updates",
                title="Actualizaciones pendientes",
                severity="Alto" if pending_count >= 3 else "Medio",
                triggered=triggered_updates,
                evidence={"pending_count": pending_count, "reboot_pending": updates.get("reboot_pending")},
                recommendation="Instalar actualizaciones pendientes y reiniciar cuando corresponda.",
                closure_criteria="No quedan pendientes y no existe reinicio requerido segun nueva consulta.",
            )
        )

    antivirus = evidence.get("antivirus")
    if isinstance(antivirus, dict) and _available(antivirus):
        preferences = antivirus.get("preferences") or {}
        if antivirus.get("enabled") is not None and antivirus.get("real_time") is not None:
            realtime_disabled_by_policy = _bool(preferences.get("DisableRealtimeMonitoring", False))
            behavior_disabled_by_policy = _bool(preferences.get("DisableBehaviorMonitoring", False))
            ioav_disabled_by_policy = _bool(preferences.get("DisableIOAVProtection", False))
            av_bad = (
                not _bool(antivirus["enabled"])
                or not _bool(antivirus["real_time"])
                or realtime_disabled_by_policy
                or behavior_disabled_by_policy
                or ioav_disabled_by_policy
            )
            results.append(
                RuleResult(
                    rule_id="ANTIVIRUS_DISABLED",
                    control="antivirus",
                    title="Antivirus o proteccion en tiempo real desactivada",
                    severity="Critico",
                    triggered=av_bad,
                    evidence={
                        "name": antivirus.get("name"),
                        "enabled": antivirus.get("enabled"),
                        "real_time": antivirus.get("real_time"),
                        "on_access_protection": antivirus.get("on_access_protection"),
                        "behavior_monitor": antivirus.get("behavior_monitor"),
                        "ioav_protection": antivirus.get("ioav_protection"),
                        "preferences": preferences,
                    },
                    recommendation="Activar la proteccion antivirus y la proteccion en tiempo real.",
                    closure_criteria="El antivirus y la proteccion en tiempo real aparecen activos.",
                )
            )
        signature_age = _int_or_none(antivirus.get("signature_age_days"))
        if signature_age is not None:
            results.append(
                RuleResult(
                    rule_id="ANTIVIRUS_SIGNATURES_OLD",
                    control="antivirus",
                    title="Firmas del antivirus desactualizadas",
                    severity="Alto",
                    triggered=signature_age > 7,
                    evidence={
                        "signature_age_days": signature_age,
                        "signature_last_updated": antivirus.get("signature_last_updated"),
                        "signatures_out_of_date": antivirus.get("signatures_out_of_date"),
                    },
                    recommendation="Actualizar las firmas del antivirus desde Seguridad de Windows o Windows Update.",
                    closure_criteria="La edad de firmas aparece en siete dias o menos.",
                )
            )
        quick_scan_age = _int_or_none(antivirus.get("quick_scan_age_days"))
        if quick_scan_age is not None:
            results.append(
                RuleResult(
                    rule_id="ANTIVIRUS_SCAN_OLD",
                    control="antivirus",
                    title="Antivirus sin escaneo reciente",
                    severity="Medio",
                    triggered=quick_scan_age > 7,
                    evidence={
                        "quick_scan_age_days": quick_scan_age,
                        "quick_scan_end_time": antivirus.get("quick_scan_end_time"),
                        "full_scan_age_days": antivirus.get("full_scan_age_days"),
                        "full_scan_end_time": antivirus.get("full_scan_end_time"),
                    },
                    recommendation="Ejecutar un analisis rapido o completo desde Seguridad de Windows y verificar nuevamente.",
                    closure_criteria="Existe un escaneo reciente registrado por el antivirus.",
                )
            )
        active_threat_count = _int_or_none(antivirus.get("active_threat_count"))
        if active_threat_count is not None:
            results.append(
                RuleResult(
                    rule_id="ANTIVIRUS_ACTIVE_THREATS",
                    control="antivirus",
                    title="Amenazas activas reportadas por el antivirus",
                    severity="Critico",
                    triggered=active_threat_count > 0,
                    evidence={
                        "active_threat_count": active_threat_count,
                        "threats": antivirus.get("threats", []),
                    },
                    recommendation="Abrir Seguridad de Windows, revisar Proteccion contra virus y amenazas, aplicar las acciones recomendadas y ejecutar un nuevo escaneo.",
                    closure_criteria="El antivirus reporta cero amenazas activas en una nueva evidencia.",
                )
            )

    connected = evidence.get("connected_devices")
    if isinstance(connected, dict) and _available(connected) and all(
        isinstance(connected.get(key), list) for key in ("usb_storage", "unsigned_drivers", "device_errors")
    ):
        usb_storage = connected["usb_storage"]
        unsigned_drivers = connected["unsigned_drivers"]
        device_errors = connected["device_errors"]
        results.append(
            RuleResult(
                rule_id="USB_STORAGE_CONNECTED",
                control="connected_devices",
                title="Dispositivo de almacenamiento USB conectado",
                severity="Medio",
                triggered=bool(usb_storage),
                evidence={
                    "usb_storage_count": len(usb_storage),
                    "usb_storage": usb_storage,
                },
                recommendation="Verificar que el USB sea de confianza y escanearlo con el antivirus antes de abrir archivos.",
                closure_criteria="No aparece almacenamiento USB conectado o el dispositivo fue aprobado por el responsable.",
            )
        )
        results.append(
            RuleResult(
                rule_id="UNSIGNED_DEVICE_DRIVER",
                control="connected_devices",
                title="Controlador de dispositivo sin firma detectado",
                severity="Alto",
                triggered=bool(unsigned_drivers),
                evidence={
                    "unsigned_driver_count": len(unsigned_drivers),
                    "unsigned_drivers": unsigned_drivers,
                },
                recommendation="Actualizar o retirar controladores sin firma desde el fabricante oficial.",
                closure_criteria="No aparecen controladores sin firma en una nueva verificacion.",
            )
        )
        results.append(
            RuleResult(
                rule_id="DEVICE_WITH_ERROR",
                control="connected_devices",
                title="Dispositivo conectado con estado de error",
                severity="Medio",
                triggered=bool(device_errors),
                evidence={
                    "device_error_count": len(device_errors),
                    "device_errors": device_errors,
                },
                recommendation="Revisar el Administrador de dispositivos y corregir o retirar dispositivos con error.",
                closure_criteria="Los dispositivos presentes aparecen con estado OK.",
            )
        )

    backup = evidence.get("backup")
    if isinstance(backup, dict) and _available(backup):
        exists_value = backup.get("exists")
        days = _int_or_none(backup.get("days_since_last_backup"))
        size = _int_or_none(backup.get("latest_size"))
        if exists_value is False or (exists_value is True and days is not None and size is not None):
            exists = _bool(exists_value)
            too_old = days is not None and days > 7
            results.append(
                RuleResult(
                    rule_id="BACKUP_OLD_OR_MISSING",
                    control="backup",
                    title="Respaldo inexistente o mayor a siete dias",
                    severity="Alto",
                    triggered=(not exists) or too_old or (size is not None and size <= 0),
                    evidence={"exists": backup.get("exists"), "days_since_last_backup": days, "latest_size": size},
                    recommendation="Ejecutar un respaldo valido y confirmar que exista un archivo reciente y no vacio.",
                    closure_criteria="Existe un archivo de respaldo reciente y no vacio.",
                )
            )

    security_result = evidence.get("security_controls")
    controls = security_result.get("data") if isinstance(security_result, dict) and security_result.get("success") is True else None
    if isinstance(controls, dict):
        uac = controls.get("uac")
        if isinstance(uac, dict) and _available(uac):
            enabled = _int_or_none(uac.get("EnableLUA"))
            if enabled is not None:
                results.append(
                    RuleResult(
                        rule_id="UAC_DISABLED",
                        control="security_controls",
                        title="Control de cuentas de usuario desactivado",
                        severity="Alto",
                        triggered=enabled == 0,
                        evidence={"EnableLUA": enabled},
                        recommendation="Activar UAC segun la linea base de seguridad de Windows.",
                        closure_criteria="Una nueva consulta muestra EnableLUA=1.",
                    )
                )
        smb1 = controls.get("smb1")
        if isinstance(smb1, dict) and _available(smb1):
            state = str(smb1.get("State", "")).lower()
            if state in {"enabled", "disabled"}:
                results.append(
                    RuleResult(
                        rule_id="SMB1_ENABLED",
                        control="security_controls",
                        title="Protocolo SMBv1 habilitado",
                        severity="Alto",
                        triggered=state == "enabled",
                        evidence={"State": smb1.get("State")},
                        recommendation="Deshabilitar SMBv1 despues de revisar compatibilidad de aplicaciones antiguas.",
                        closure_criteria="Una nueva consulta muestra SMB1Protocol deshabilitado.",
                    )
                )
        rdp = controls.get("rdp")
        if isinstance(rdp, dict):
            raw = rdp.get("raw")
            raw_rdp = raw.get("rdp") if isinstance(raw, dict) else None
            raw_nla = raw.get("nla") if isinstance(raw, dict) else None
            if (
                isinstance(raw_rdp, dict) and _available(raw_rdp)
                and isinstance(raw_nla, dict) and _available(raw_nla)
                and _int_or_none(raw_rdp.get("fDenyTSConnections")) is not None
                and _int_or_none(raw_nla.get("UserAuthentication")) is not None
            ):
                rdp_enabled = _int_or_none(raw_rdp["fDenyTSConnections"]) == 0
                nla_required = _int_or_none(raw_nla["UserAuthentication"]) == 1
                results.append(
                    RuleResult(
                        rule_id="RDP_NLA_DISABLED",
                        control="security_controls",
                        title="RDP activo sin autenticacion de nivel de red",
                        severity="Alto",
                        triggered=rdp_enabled and not nla_required,
                        evidence={"rdp_enabled": rdp_enabled, "nla_required": nla_required},
                        recommendation="Exigir Network Level Authentication para conexiones RDP.",
                        closure_criteria="Una nueva consulta confirma RDP deshabilitado o NLA obligatorio.",
                    )
                )
    return results
