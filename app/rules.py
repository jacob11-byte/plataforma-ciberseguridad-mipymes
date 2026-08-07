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


AUTHORIZED_ADMIN_NAMES = {"administrador", "administrator", "soporte"}
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


def evaluate_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    results: list[RuleResult] = []
    if "firewall" in evidence:
        firewall = evidence.get("firewall") or {}
        if firewall.get("status") != "not_supported":
            public_enabled = _bool(firewall.get("public", True))
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

    ports = evidence.get("listening_ports") or []
    services = evidence.get("services") or []
    port_3389 = any(int(item.get("port", item)) == 3389 for item in ports if str(item.get("port", item)).isdigit())
    term_service = any(
        str(item.get("name", "")).lower() == "termservice" and _bool(item.get("running", False))
        for item in services
        if isinstance(item, dict)
    )
    if "listening_ports" in evidence or "services" in evidence:
        results.append(
            RuleResult(
                rule_id="RDP_EXPOSED",
                control="ports",
                title="RDP activo o puerto 3389 expuesto",
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
    if "services" in evidence:
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

    if "local_administrators" in evidence or "local_admins" in evidence:
        admins = evidence.get("local_administrators") or evidence.get("local_admins") or []
        unauthorized = [name for name in admins if _admin_name(name) not in AUTHORIZED_ADMIN_NAMES]
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

    if "updates" in evidence:
        updates = evidence.get("updates") or {}
        if updates.get("status") in {"not_supported", "error"}:
            pending_count = 0
            triggered_updates = False
        else:
            pending_count = int(updates.get("pending_count") or 0)
            triggered_updates = pending_count > 0 or _bool(updates.get("reboot_pending", False))
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

    if "antivirus" in evidence:
        antivirus = evidence.get("antivirus") or {}
        av_unknown = antivirus.get("status") in {"not_supported", "unavailable", "error"}
        preferences = antivirus.get("preferences") or {}
        realtime_disabled_by_policy = _bool(preferences.get("DisableRealtimeMonitoring", False))
        behavior_disabled_by_policy = _bool(preferences.get("DisableBehaviorMonitoring", False))
        ioav_disabled_by_policy = _bool(preferences.get("DisableIOAVProtection", False))
        av_bad = False if av_unknown else (
            not _bool(antivirus.get("enabled", True))
            or not _bool(antivirus.get("real_time", True))
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
        results.append(
            RuleResult(
                rule_id="ANTIVIRUS_SIGNATURES_OLD",
                control="antivirus",
                title="Firmas del antivirus desactualizadas",
                severity="Alto",
                triggered=signature_age is not None and signature_age > 7,
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
        results.append(
            RuleResult(
                rule_id="ANTIVIRUS_SCAN_OLD",
                control="antivirus",
                title="Antivirus sin escaneo reciente",
                severity="Medio",
                triggered=quick_scan_age is not None and quick_scan_age > 7,
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
        active_threat_count = _int_or_none(antivirus.get("active_threat_count")) or 0
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

    if "connected_devices" in evidence:
        connected = evidence.get("connected_devices") or {}
        usb_storage = connected.get("usb_storage") or []
        unsigned_drivers = connected.get("unsigned_drivers") or []
        device_errors = connected.get("device_errors") or []
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

    if "backup" in evidence:
        backup = evidence.get("backup") or {}
        if backup.get("status") != "not_configured":
            exists = _bool(backup.get("exists", False))
            days = backup.get("days_since_last_backup")
            too_old = days is None or int(days) > 7
            results.append(
                RuleResult(
                    rule_id="BACKUP_OLD_OR_MISSING",
                    control="backup",
                    title="Respaldo inexistente o mayor a siete dias",
                    severity="Alto",
                    triggered=(not exists) or too_old,
                    evidence={"exists": backup.get("exists"), "days_since_last_backup": days, "latest_size": backup.get("latest_size")},
                    recommendation="Ejecutar un respaldo valido y confirmar que exista un archivo reciente y no vacio.",
                    closure_criteria="Existe un archivo de respaldo reciente y no vacio.",
                )
            )
    return results
