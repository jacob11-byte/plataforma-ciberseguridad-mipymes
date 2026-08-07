from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


INSUFFICIENT = "No existe evidencia suficiente para determinarlo."

SEVERITY_WEIGHT = {
    "critico": 4,
    "critical": 4,
    "alto": 3,
    "high": 3,
    "medio": 2,
    "medium": 2,
    "bajo": 1,
    "low": 1,
}


@dataclass(frozen=True)
class EvidenceRef:
    type: str
    id: int | str
    label: str

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "id": self.id, "label": self.label}


def device_ai_summary(db: Any, device_id: str) -> dict[str, Any]:
    context = build_device_context(db, device_id)
    if not context["device"]:
        return insufficient_response()
    return analyze_context(context)


def company_ai_summary(db: Any) -> dict[str, Any]:
    context = build_company_context(db)
    if not context["devices"]:
        return insufficient_response()
    return analyze_context(context)


def answer_device_question(db: Any, device_id: str, question: str) -> dict[str, Any]:
    context = build_device_context(db, device_id)
    if not context["device"]:
        return insufficient_response()
    return answer_question(context, question)


def answer_company_question(db: Any, question: str) -> dict[str, Any]:
    context = build_company_context(db)
    if not context["devices"]:
        return insufficient_response()
    return answer_question(context, question)


def build_device_context(db: Any, device_id: str) -> dict[str, Any]:
    device = db.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
    findings = rows(
        db.execute(
            "SELECT * FROM findings WHERE device_id=? ORDER BY updated_at DESC LIMIT 80",
            (device_id,),
        ).fetchall()
    )
    scans = rows(
        db.execute(
            "SELECT * FROM scans WHERE device_id=? ORDER BY created_at DESC LIMIT 30",
            (device_id,),
        ).fetchall()
    )
    evidences = rows(
        db.execute(
            """
            SELECT e.*, s.scan_type FROM evidences e
            JOIN scans s ON s.id=e.scan_id
            WHERE e.device_id=?
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT 160
            """,
            (device_id,),
        ).fetchall()
    )
    diffs = rows(
        db.execute(
            "SELECT * FROM snapshot_diffs WHERE device_id=? ORDER BY created_at DESC LIMIT 10",
            (device_id,),
        ).fetchall()
    )
    tasks = rows(
        db.execute(
            "SELECT * FROM tasks WHERE device_id=? ORDER BY created_at DESC LIMIT 20",
            (device_id,),
        ).fetchall()
    )
    return {
        "scope": "device",
        "device": dict(device) if device else None,
        "devices": [dict(device)] if device else [],
        "findings": findings,
        "scans": scans,
        "evidences": evidences,
        "diffs": diffs,
        "tasks": tasks,
    }


def build_company_context(db: Any) -> dict[str, Any]:
    devices = rows(db.execute("SELECT * FROM devices ORDER BY last_seen DESC NULLS LAST LIMIT 80").fetchall())
    findings = rows(db.execute("SELECT * FROM findings ORDER BY updated_at DESC LIMIT 200").fetchall())
    scans = rows(db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 80").fetchall())
    evidences = rows(
        db.execute(
            """
            SELECT e.*, s.scan_type FROM evidences e
            JOIN scans s ON s.id=e.scan_id
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT 240
            """
        ).fetchall()
    )
    diffs = rows(db.execute("SELECT * FROM snapshot_diffs ORDER BY created_at DESC LIMIT 40").fetchall())
    tasks = rows(db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 80").fetchall())
    return {
        "scope": "company",
        "device": None,
        "devices": devices,
        "findings": findings,
        "scans": scans,
        "evidences": evidences,
        "diffs": diffs,
        "tasks": tasks,
    }


def analyze_context(context: dict[str, Any]) -> dict[str, Any]:
    open_findings = [item for item in context["findings"] if item.get("status") != "resolved"]
    priority_findings = sorted(open_findings, key=finding_priority, reverse=True)
    latest_scan = context["scans"][0] if context["scans"] else None
    latest_diff = context["diffs"][0] if context["diffs"] else None
    evidence_refs = refs_for_findings(priority_findings[:5])
    if latest_scan:
        evidence_refs.append(EvidenceRef("scan", latest_scan["id"], f"Revision {latest_scan['scan_type']}").as_dict())
    if latest_diff:
        evidence_refs.append(EvidenceRef("snapshot_diff", latest_diff["id"], "Cambio entre snapshots").as_dict())

    posture = posture_level(open_findings)
    return {
        "summary": build_summary(context, open_findings, posture, latest_scan),
        "risk_level": posture,
        "priorities": build_priorities(priority_findings),
        "changes": build_changes(context["diffs"]),
        "anomalies": build_anomalies(context),
        "recommendations": build_recommendations(priority_findings, context),
        "evidence_refs": evidence_refs,
        "insufficient_evidence": not bool(context["scans"] or context["evidences"] or context["findings"]),
    }


def answer_question(context: dict[str, Any], question: str) -> dict[str, Any]:
    normalized = question.lower().strip()
    analysis = analyze_context(context)
    if analysis["insufficient_evidence"]:
        return insufficient_response()

    if any(term in normalized for term in ("riesgo", "alto", "critico")):
        answer = analysis["summary"]
        return answer_response(answer, analysis["evidence_refs"])
    if any(term in normalized for term in ("cambio", "cambio desde", "ultimo analisis", "snapshot")):
        changes = analysis["changes"]
        if not changes:
            return insufficient_response()
        answer = "Cambios relevantes: " + " ".join(changes[:3])
        refs = [ref for ref in analysis["evidence_refs"] if ref["type"] == "snapshot_diff"]
        return answer_response(answer, refs)
    if any(term in normalized for term in ("primero", "prioridad", "corregir")):
        priorities = analysis["priorities"]
        if not priorities:
            return answer_response("No hay problemas abiertos que priorizar con la evidencia actual.", analysis["evidence_refs"])
        first = priorities[0]
        answer = f"Primero corrige: {first['title']}. Motivo: severidad {first['severity']} y estado {first['status']}. Paso sugerido: {first['recommendation']}"
        return answer_response(answer, first["evidence_refs"])
    if any(term in normalized for term in ("equipo", "equipos", "atencion")):
        devices = devices_requiring_attention(context)
        if not devices:
            return answer_response("No hay equipos con problemas abiertos en la evidencia actual.", analysis["evidence_refs"])
        names = ", ".join(item["name"] for item in devices[:5])
        return answer_response(f"Equipos que requieren atencion: {names}.", analysis["evidence_refs"])

    return answer_response(
        "Puedo responder con la evidencia almacenada sobre riesgo, cambios, prioridades y equipos que requieren atencion.",
        analysis["evidence_refs"],
    )


def build_summary(context: dict[str, Any], open_findings: list[dict[str, Any]], posture: str, latest_scan: dict[str, Any] | None) -> str:
    device_count = len(context["devices"])
    scan_text = "sin revision registrada"
    if latest_scan:
        scan_text = f"ultima revision {latest_scan['scan_type']} con {latest_scan.get('modules_success') or 0} modulos correctos y {latest_scan.get('modules_error') or 0} con error"
    if context["scope"] == "device":
        device = context["device"] or {}
        name = device.get("name") or device.get("hostname") or device.get("device_id") or "este equipo"
        return f"{name} tiene postura {posture}. Hay {len(open_findings)} problemas abiertos y {scan_text}."
    return f"La empresa tiene {device_count} equipos registrados, postura general {posture}, {len(open_findings)} problemas abiertos y {scan_text}."


def build_priorities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priorities = []
    for finding in findings[:8]:
        priorities.append(
            {
                "id": finding["id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "status": finding["status"],
                "control": finding["control"],
                "recommendation": finding["recommendation"],
                "evidence_refs": [EvidenceRef("finding", finding["id"], finding["title"]).as_dict()],
            }
        )
    return priorities


def build_changes(diffs: list[dict[str, Any]]) -> list[str]:
    changes = []
    for diff_row in diffs[:3]:
        diff = parse_json(diff_row.get("diff_json"))
        summary = diff.get("summary") or {}
        total = int(summary.get("total_changes") or 0)
        if total:
            changes.append(
                f"Snapshot {diff_row.get('previous_snapshot_id')} -> {diff_row.get('current_snapshot_id')}: {total} cambios ({summary.get('added') or 0} agregados, {summary.get('removed') or 0} eliminados, {summary.get('changed') or 0} modificados)."
            )
    return changes


def build_anomalies(context: dict[str, Any]) -> list[str]:
    anomalies = []
    open_findings = [item for item in context["findings"] if item.get("status") != "resolved"]
    controls = {item.get("control") for item in open_findings}
    if {"connected_devices", "backup"} <= controls:
        anomalies.append("Hay dispositivos conectados y respaldo pendiente; conviene revisar USB antes de mover o respaldar informacion.")
    if {"administrators", "updates"} <= controls:
        anomalies.append("Hay administradores no autorizados junto con actualizaciones pendientes; aumenta la prioridad de correccion.")
    recent_failures = [task for task in context["tasks"] if task.get("status") == "failed"]
    if recent_failures:
        anomalies.append(f"Existen {len(recent_failures)} solicitudes fallidas recientes; revisa conectividad del agente o permisos locales.")
    if not anomalies and context["diffs"]:
        anomalies.append("Existen cambios entre snapshots; revisa la pestana Cambios para confirmar si eran esperados.")
    return anomalies


def build_recommendations(findings: list[dict[str, Any]], context: dict[str, Any]) -> list[str]:
    recommendations = []
    for finding in findings[:5]:
        recommendations.append(f"{finding['title']}: {finding['recommendation']}")
    if not recommendations and context["scans"]:
        recommendations.append("No hay problemas abiertos; programa revisiones periodicas para mantener evidencia actualizada.")
    if not recommendations:
        recommendations.append(INSUFFICIENT)
    return recommendations


def devices_requiring_attention(context: dict[str, Any]) -> list[dict[str, Any]]:
    by_device: dict[str, dict[str, Any]] = {}
    names = {item["device_id"]: item.get("name") or item.get("hostname") or item["device_id"] for item in context["devices"]}
    for finding in context["findings"]:
        if finding.get("status") == "resolved":
            continue
        device_id = finding["device_id"]
        current = by_device.setdefault(device_id, {"device_id": device_id, "name": names.get(device_id, device_id), "score": 0})
        current["score"] += SEVERITY_WEIGHT.get(str(finding.get("severity", "")).lower(), 1)
    return sorted(by_device.values(), key=lambda item: item["score"], reverse=True)


def posture_level(open_findings: list[dict[str, Any]]) -> str:
    severities = [str(item.get("severity", "")).lower() for item in open_findings]
    if any(SEVERITY_WEIGHT.get(value, 0) >= 4 for value in severities):
        return "critica"
    if any(SEVERITY_WEIGHT.get(value, 0) >= 3 for value in severities):
        return "alta"
    if open_findings:
        return "media"
    return "estable"


def finding_priority(finding: dict[str, Any]) -> int:
    return SEVERITY_WEIGHT.get(str(finding.get("severity", "")).lower(), 1)


def refs_for_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [EvidenceRef("finding", item["id"], item["title"]).as_dict() for item in findings]


def answer_response(answer: str, refs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"answer": answer, "evidence_refs": refs, "insufficient_evidence": False}


def insufficient_response() -> dict[str, Any]:
    return {
        "summary": INSUFFICIENT,
        "risk_level": "sin_evidencia",
        "priorities": [],
        "changes": [],
        "anomalies": [],
        "recommendations": [INSUFFICIENT],
        "answer": INSUFFICIENT,
        "evidence_refs": [],
        "insufficient_evidence": True,
    }


def rows(values: list[Any]) -> list[dict[str, Any]]:
    return [dict(value) for value in values]


def parse_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
