from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .ai_service import answer_company_question, answer_device_question, company_ai_summary, device_ai_summary
from .rules import evaluate_rules
from .storage import connect, generate_device_id, generate_token, init_db, insert_returning_id, json_dumps

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

CONTROL_TABS = {
    "system_info": "Informacion del equipo",
    "firewall": "Firewall",
    "ports": "Puertos",
    "services": "Servicios remotos",
    "administrators": "Administradores",
    "updates": "Actualizaciones",
    "antivirus": "Antivirus",
    "threats": "Amenazas",
    "backup": "Respaldos",
    "connected_devices": "Dispositivos",
    "system_inventory_v2": "Inventario avanzado",
    "security_controls": "Controles de seguridad",
    "software_inventory": "Programas instalados",
    "process_inventory": "Procesos activos",
    "security_eventlog": "Registro de seguridad",
}

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SESSION_COOKIE = "cybercheck_session"
SESSION_MAX_AGE = 60 * 60 * 8
AGENT_ONLINE_WINDOW_SECONDS = 10 * 60

app = FastAPI(title="CyberCheck MIPYME", version="1.0.0")


class RegisterRequest(BaseModel):
    registration_code: str = Field(min_length=4)
    company_name: str = Field(default="MIPYME Principal", min_length=2)
    hostname: str = Field(min_length=1)
    os_version: str | None = None
    windows_edition: str | None = None
    architecture: str | None = None
    ip_address: str | None = None
    agent_version: str = "0.1.0"


class HeartbeatRequest(BaseModel):
    device_id: str
    agent_version: str
    timestamp: str | None = None


class ScanRequest(BaseModel):
    device_id: str
    scan_type: str
    evidence: dict[str, Any]


class TaskRequest(BaseModel):
    device_id: str
    task_type: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class LoginRequest(BaseModel):
    username: str
    password: str


class AiChatRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@app.on_event("startup")
def startup() -> None:
    init_db()


def _admin_username() -> str:
    return os.getenv("ADMIN_USERNAME", "admin")


def _admin_password() -> str:
    return os.getenv("ADMIN_PASSWORD", "admin123")


def _session_secret() -> str:
    configured = os.getenv("SESSION_SECRET")
    if configured:
        return configured
    return _admin_password()


def _sign(value: str) -> str:
    signature = hmac.new(_session_secret().encode("utf-8"), value.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _create_session(username: str) -> str:
    expires = str(int(time.time()) + SESSION_MAX_AGE)
    nonce = secrets.token_urlsafe(12)
    payload = f"{username}|{expires}|{nonce}"
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{token}.{_sign(token)}"


def _read_session(request: Request) -> str | None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie or "." not in cookie:
        return None
    token, signature = cookie.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(token)):
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        payload = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        username, expires, _nonce = payload.split("|", 2)
    except ValueError:
        return None
    if int(expires) < int(time.time()):
        return None
    return username


def _require_user(request: Request) -> str:
    username = _read_session(request)
    if not username:
        raise HTTPException(status_code=401, detail="Sesion requerida")
    return username


def _registration_code() -> str:
    return os.getenv("AGENT_REGISTRATION_CODE", "cybercheck-register-dev")


def _device_for_token(device_id: str, token: str | None) -> dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    token = token.removeprefix("Bearer ").strip()
    with connect() as db:
        row = db.execute(
            """
            SELECT d.* FROM devices d
            JOIN agent_credentials c ON c.device_id = d.device_id
            WHERE d.device_id = ? AND c.token = ? AND c.active = ?
            """,
            (device_id, token, True),
        ).fetchone()
        if row:
            db.execute("UPDATE agent_credentials SET last_used_at=CURRENT_TIMESTAMP WHERE device_id=? AND token=?", (device_id, token))
            return dict(row)
        raise HTTPException(status_code=403, detail="Token invalido para el equipo")


@app.get("/")
def index(request: Request):
    if not _read_session(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse(WEB_DIR / "index.html")


@app.get("/devices/{device_id}")
def device_page(device_id: str, request: Request):
    if not _read_session(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse(WEB_DIR / "device.html")


@app.get("/login")
def login_page(request: Request):
    if _read_session(request):
        return RedirectResponse("/", status_code=302)
    return FileResponse(WEB_DIR / "login.html")


@app.get("/static/styles.css")
def styles() -> FileResponse:
    return FileResponse(WEB_DIR / "styles.css", media_type="text/css")


@app.get("/static/app.js")
def script() -> FileResponse:
    return FileResponse(WEB_DIR / "app.js", media_type="application/javascript")


@app.get("/static/device.js")
def device_script() -> FileResponse:
    return FileResponse(WEB_DIR / "device.js", media_type="application/javascript")


@app.post("/api/login")
def login(payload: LoginRequest) -> JSONResponse:
    valid_user = hmac.compare_digest(payload.username, _admin_username())
    valid_password = hmac.compare_digest(payload.password, _admin_password())
    if not valid_user or not valid_password:
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    response = JSONResponse({"ok": True, "username": payload.username})
    response.set_cookie(
        SESSION_COOKIE,
        _create_session(payload.username),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() != "false",
        samesite="lax",
    )
    return response


@app.post("/api/logout")
def logout() -> Response:
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
def me(request: Request) -> dict[str, Any]:
    return {"username": _require_user(request)}


@app.post("/api/register")
def register(payload: RegisterRequest) -> dict[str, Any]:
    if not hmac.compare_digest(payload.registration_code, _registration_code()):
        raise HTTPException(status_code=403, detail="Codigo de registro invalido")
    with connect() as db:
        company = db.execute("SELECT id FROM companies WHERE name = ?", (payload.company_name,)).fetchone()
        company_id = company["id"] if company else insert_returning_id(
            db, "INSERT INTO companies(name) VALUES (?)", (payload.company_name,)
        )
        device_id = generate_device_id()
        token = generate_token()
        db.execute(
            """
            INSERT INTO devices(device_id, company_id, name, hostname, os_version, windows_edition,
                architecture, ip_address, agent_version, token, installed_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (
                device_id,
                company_id,
                payload.hostname,
                payload.hostname,
                payload.os_version,
                payload.windows_edition,
                payload.architecture,
                payload.ip_address,
                payload.agent_version,
                token,
            ),
        )
        db.execute(
            "INSERT INTO agent_credentials(device_id, token) VALUES (?, ?)",
            (device_id, token),
        )
        return {"device_id": device_id, "token": token, "hostname": payload.hostname}


@app.post("/api/agent/heartbeat")
def heartbeat(payload: HeartbeatRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _device_for_token(payload.device_id, authorization)
    with connect() as db:
        db.execute(
            "UPDATE devices SET last_seen=CURRENT_TIMESTAMP, agent_version=? WHERE device_id=?",
            (payload.agent_version, payload.device_id),
        )
        return {"ok": True, "device_id": payload.device_id}


@app.post("/api/agent/results")
def receive_results(payload: ScanRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _device_for_token(payload.device_id, authorization)
    if payload.scan_type not in ALLOWED_TASKS:
        raise HTTPException(status_code=400, detail="Tipo de tarea no permitido")

    rule_results = evaluate_rules(payload.evidence)
    with connect() as db:
        db.execute("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?", (payload.device_id,))
        system_info = payload.evidence.get("system_info") or {}
        if system_info:
            db.execute(
                """
                UPDATE devices SET
                    name=?,
                    hostname=?,
                    os_version=?,
                    windows_edition=?,
                    architecture=?,
                    ip_address=?
                WHERE device_id=?
                """,
                (
                    system_info.get("hostname") or payload.device_id,
                    system_info.get("hostname"),
                    system_info.get("os_version"),
                    system_info.get("windows_edition"),
                    system_info.get("architecture"),
                    system_info.get("ip_address"),
                    payload.device_id,
                ),
            )
        scan_id = insert_returning_id(
            db,
            """
            INSERT INTO scans(device_id, scan_type, status, completed_at, duration_ms, modules_success, modules_error)
            VALUES (?, ?, 'completed', CURRENT_TIMESTAMP, ?, ?, ?)
            """,
            (
                payload.device_id,
                payload.scan_type,
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("duration_ms")),
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("modules_success")),
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("modules_error")),
            ),
        )
        for control, value in status_evidence(payload.evidence).items():
            db.execute(
                "INSERT INTO evidences(scan_id, device_id, control, result_json) VALUES (?, ?, ?, ?)",
                (scan_id, payload.device_id, f"status_{control}", json_dumps(value)),
            )
        maybe_store_snapshot(db, payload.device_id, scan_id, payload.evidence)
        for result in rule_results:
            db.execute(
                "INSERT INTO evidences(scan_id, device_id, control, result_json) VALUES (?, ?, ?, ?)",
                (scan_id, payload.device_id, result.control, json_dumps(result.evidence)),
            )
            existing = db.execute(
                "SELECT * FROM findings WHERE device_id = ? AND rule_id = ?",
                (payload.device_id, result.rule_id),
            ).fetchone()
            if result.triggered:
                if existing:
                    previous = existing["status"]
                    new_status = "reopened" if previous == "resolved" else "open"
                    db.execute(
                        """
                        UPDATE findings SET status=?, severity=?, last_scan_id=?, resolved_scan_id=NULL,
                            updated_at=CURRENT_TIMESTAMP
                        WHERE id=?
                        """,
                        (new_status, result.severity, scan_id, existing["id"]),
                    )
                    if previous != new_status:
                        db.execute(
                            "INSERT INTO history(finding_id, previous_status, new_status, note, scan_id) VALUES (?, ?, ?, ?, ?)",
                            (existing["id"], previous, new_status, "Condicion insegura detectada nuevamente.", scan_id),
                        )
                else:
                    finding_id = insert_returning_id(
                        db,
                        """
                        INSERT INTO findings(device_id, rule_id, control, title, severity, status, recommendation,
                            closure_criteria, first_scan_id, last_scan_id)
                        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
                        """,
                        (
                            payload.device_id,
                            result.rule_id,
                            result.control,
                            result.title,
                            result.severity,
                            result.recommendation,
                            result.closure_criteria,
                            scan_id,
                            scan_id,
                        ),
                    )
                    db.execute(
                        "INSERT INTO history(finding_id, previous_status, new_status, note, scan_id) VALUES (?, NULL, 'open', ?, ?)",
                        (finding_id, "Hallazgo generado por el motor de reglas.", scan_id),
                    )
            elif existing and existing["status"] in {"open", "reopened"}:
                db.execute(
                    """
                    UPDATE findings SET status='resolved', last_scan_id=?, resolved_scan_id=?,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id=?
                    """,
                    (scan_id, scan_id, existing["id"]),
                )
                db.execute(
                    "INSERT INTO history(finding_id, previous_status, new_status, note, scan_id) VALUES (?, ?, 'resolved', ?, ?)",
                    (existing["id"], existing["status"], "Correccion verificada con nueva evidencia tecnica.", scan_id),
                )
        return {"scan_id": scan_id, "evaluated_rules": len(rule_results)}


@app.get("/api/agent/tasks")
def agent_tasks(
    device_id: str,
    max_tasks: int = Query(default=10, ge=1, le=10),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _device_for_token(device_id, authorization)
    with connect() as db:
        rows = db.execute(
            """
            SELECT * FROM tasks
            WHERE device_id = ? AND status IN ('pending', 'delivered')
            ORDER BY created_at
            LIMIT ?
            """,
            (device_id, max_tasks),
        ).fetchall()
        task_ids = [row["id"] for row in rows if row["status"] == "pending"]
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            db.execute(
                f"UPDATE tasks SET status='delivered', delivered_at=CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                task_ids,
            )
        return {"tasks": [dict(row) for row in rows]}


@app.post("/api/tasks")
def create_task(payload: TaskRequest, request: Request) -> dict[str, Any]:
    _require_user(request)
    if payload.task_type not in ALLOWED_TASKS:
        raise HTTPException(status_code=400, detail="Tipo de tarea no permitido")
    with connect() as db:
        device = db.execute("SELECT device_id FROM devices WHERE device_id = ?", (payload.device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Equipo no existe")
        task_id = insert_returning_id(
            db,
            "INSERT INTO tasks(device_id, task_type, parameters_json) VALUES (?, ?, ?)",
            (payload.device_id, payload.task_type, json_dumps(payload.parameters)),
        )
        return {"task_id": task_id, "status": "pending"}


@app.post("/api/devices/{device_id}/reconnect")
def reconnect_device(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        device = db.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Equipo no existe")
        view = device_view(dict(device))
    return {
        "device_id": device_id,
        "agent_status": view["agent_status"],
        "agent_status_label": view["agent_status_label"],
        "can_remote_start": False,
        "message": (
            "El servidor no puede iniciar un programa dentro de Windows si el agente esta desconectado. "
            "Ejecuta uno de estos comandos en la computadora del agente para forzar la reconexion."
        ),
        "commands": [
            "Start-ScheduledTask -TaskName \"CyberCheck MIPYME Agent User\"",
            "cd C:\\pg2; py -3.12 agent\\windows_agent.py --config agent\\agent_config.render.json --poll-once --max-tasks 10",
        ],
    }


@app.post("/api/devices/{device_id}/disconnect")
def disconnect_device(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        device = db.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Equipo no existe")
        db.execute("UPDATE agent_credentials SET active=? WHERE device_id=?", (False, device_id))
        db.execute(
            "UPDATE tasks SET status='canceled', completed_at=CURRENT_TIMESTAMP WHERE device_id=? AND status IN ('pending', 'delivered')",
            (device_id,),
        )
    return {
        "device_id": device_id,
        "status": "disconnected",
        "message": "Agente desconectado. Sus credenciales quedaron desactivadas y las tareas pendientes fueron canceladas.",
    }


@app.post("/api/devices/{device_id}/reactivate")
def reactivate_device(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        device = db.execute("SELECT device_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Equipo no existe")
        db.execute("UPDATE agent_credentials SET active=? WHERE device_id=?", (True, device_id))
    return {
        "device_id": device_id,
        "status": "active",
        "message": "Agente reactivado. El token existente puede volver a enviar heartbeat y evidencia.",
    }


@app.get("/api/devices/{device_id}/detail")
def device_detail(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        device = db.execute(
            """
            SELECT d.*,
                EXISTS(SELECT 1 FROM agent_credentials c WHERE c.device_id=d.device_id AND c.active=?) AS credential_active
            FROM devices d
            WHERE d.device_id = ?
            """,
            (True, device_id),
        ).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Equipo no existe")
        device_row = device_view(dict(device))
        scans = [dict(row) for row in db.execute(
            "SELECT * FROM scans WHERE device_id=? ORDER BY created_at DESC LIMIT 50",
            (device_id,),
        ).fetchall()]
        tasks = [dict(row) for row in db.execute(
            "SELECT * FROM tasks WHERE device_id=? ORDER BY created_at DESC LIMIT 50",
            (device_id,),
        ).fetchall()]
        evidences = [dict(row) for row in db.execute(
            """
            SELECT e.*, s.scan_type FROM evidences e
            JOIN scans s ON s.id = e.scan_id
            WHERE e.device_id=?
            ORDER BY e.created_at DESC, e.id DESC
            LIMIT 300
            """,
            (device_id,),
        ).fetchall()]
        findings = [dict(row) for row in db.execute(
            "SELECT * FROM findings WHERE device_id=? ORDER BY updated_at DESC",
            (device_id,),
        ).fetchall()]
        snapshots = [dict(row) for row in db.execute(
            "SELECT * FROM inventory_snapshots WHERE device_id=? ORDER BY created_at DESC LIMIT 20",
            (device_id,),
        ).fetchall()]
        diffs = [dict(row) for row in db.execute(
            "SELECT * FROM snapshot_diffs WHERE device_id=? ORDER BY created_at DESC LIMIT 20",
            (device_id,),
        ).fetchall()]
        finding_ids = [finding["id"] for finding in findings]
        history = []
        if finding_ids:
            placeholders = ",".join("?" for _ in finding_ids)
            history = [dict(row) for row in db.execute(
                f"SELECT * FROM history WHERE finding_id IN ({placeholders}) ORDER BY created_at DESC LIMIT 80",
                finding_ids,
            ).fetchall()]
    latest_controls = latest_controls_from_evidences(evidences)
    control_matrix = build_control_matrix(latest_controls, findings)
    latest_scan = scans[0] if scans else None
    latest_full_scan = next((scan for scan in scans if scan["scan_type"] == "FULL_SCAN"), None)
    latest_completed_task = next((task for task in tasks if task["status"] == "completed"), None)
    open_findings = [finding for finding in findings if finding["status"] != "resolved"]
    return {
        "device": device_row,
        "summary": {
            "last_heartbeat": device_row.get("last_seen"),
            "last_requested_task": tasks[0] if tasks else None,
            "last_completed_task": latest_completed_task,
            "last_full_scan": latest_full_scan,
            "last_scan": latest_scan,
            "agent_version": device_row.get("agent_version"),
            "last_scan_duration_ms": latest_scan.get("duration_ms") if latest_scan else None,
            "modules_success": latest_scan.get("modules_success") if latest_scan else None,
            "modules_error": latest_scan.get("modules_error") if latest_scan else None,
            "controls_pass": len([item for item in control_matrix if item["status"] == "PASS"]),
            "open_findings": len(open_findings),
        },
        "control_matrix": control_matrix,
        "controls": latest_controls,
        "scans": scans,
        "tasks": tasks,
        "findings": findings,
        "evidences": evidences,
        "history": history,
        "snapshots": snapshots,
        "diffs": diffs,
    }


@app.post("/api/agent/tasks/{task_id}/complete")
def complete_task(task_id: int, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Tarea no existe")
        _device_for_token(task["device_id"], authorization)
        db.execute("UPDATE tasks SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?", (task_id,))
        return {"status": "completed"}


@app.post("/api/agent/tasks/{task_id}/fail")
def fail_task(task_id: int, authorization: str | None = Header(default=None)) -> dict[str, str]:
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Tarea no existe")
        _device_for_token(task["device_id"], authorization)
        db.execute("UPDATE tasks SET status='failed', completed_at=CURRENT_TIMESTAMP WHERE id=?", (task_id,))
        return {"status": "failed"}


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        evidences = [dict(row) for row in db.execute("SELECT * FROM evidences ORDER BY created_at DESC LIMIT 120")]
        devices = [device_view(dict(row)) for row in db.execute(
            """
            SELECT d.*,
                EXISTS(SELECT 1 FROM agent_credentials c WHERE c.device_id=d.device_id AND c.active=?) AS credential_active
            FROM devices d
            ORDER BY last_seen DESC NULLS LAST
            """,
            (True,),
        )]
        findings = [dict(row) for row in db.execute("SELECT * FROM findings ORDER BY updated_at DESC")]
        open_findings = [finding for finding in findings if finding["status"] != "resolved"]
        return {
            "devices": devices,
            "findings": findings,
            "evidences": evidences,
            "scans": [dict(row) for row in db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 20")],
            "tasks": [dict(row) for row in db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 20")],
            "history": [dict(row) for row in db.execute("SELECT * FROM history ORDER BY created_at DESC LIMIT 40")],
            "summary": {
                "devices": len(devices),
                "online_devices": len([device for device in devices if device["agent_status"] == "online"]),
                "open_findings": len(open_findings),
                "critical": len([finding for finding in open_findings if finding["severity"].lower() in {"critico", "critical"}]),
                "high": len([finding for finding in open_findings if finding["severity"].lower() in {"alto", "high"}]),
                "medium": len([finding for finding in open_findings if finding["severity"].lower() in {"medio", "medium"}]),
                "resolved": len([finding for finding in findings if finding["status"] == "resolved"]),
            },
        }


@app.get("/api/ai/company-summary")
def ai_company_summary(request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        return company_ai_summary(db)


@app.post("/api/ai/company-chat")
def ai_company_chat(payload: AiChatRequest, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        return answer_company_question(db, payload.question)


@app.get("/api/devices/{device_id}/ai-summary")
def ai_device_summary(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        return device_ai_summary(db, device_id)


@app.post("/api/devices/{device_id}/ai-chat")
def ai_device_chat(device_id: str, payload: AiChatRequest, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        return answer_device_question(db, device_id, payload.question)


def latest_controls_from_evidences(evidences: list[dict[str, Any]]) -> dict[str, Any]:
    controls: dict[str, Any] = {}
    for evidence in evidences:
        control = str(evidence.get("control") or "")
        if not control.startswith("status_"):
            continue
        key = control.replace("status_", "", 1)
        if key not in controls:
            controls[key] = {
                "control": key,
                "label": CONTROL_TABS.get(key, key),
                "scan_id": evidence.get("scan_id"),
                "scan_type": evidence.get("scan_type"),
                "created_at": evidence.get("created_at"),
                "data": json_loads(evidence.get("result_json")),
            }
    if "antivirus" in controls and "threats" not in controls:
        controls["threats"] = {
            "control": "threats",
            "label": CONTROL_TABS["threats"],
            "scan_id": controls["antivirus"].get("scan_id"),
            "scan_type": controls["antivirus"].get("scan_type"),
            "created_at": controls["antivirus"].get("created_at"),
            "data": {
                "active_threat_count": (controls["antivirus"].get("data") or {}).get("active_threat_count"),
                "threats": (controls["antivirus"].get("data") or {}).get("threats", []),
            },
        }
    return controls


def maybe_store_snapshot(db: Any, device_id: str, scan_id: int, evidence: dict[str, Any]) -> None:
    snapshot = snapshot_from_evidence(evidence)
    if not snapshot:
        return
    snapshot_hash = hashlib.sha256(json_dumps(snapshot).encode("utf-8")).hexdigest()
    previous = db.execute(
        "SELECT * FROM inventory_snapshots WHERE device_id=? ORDER BY created_at DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    current_id = insert_returning_id(
        db,
        """
        INSERT INTO inventory_snapshots(device_id, scan_id, snapshot_type, snapshot_json, hash)
        VALUES (?, ?, 'endpoint', ?, ?)
        """,
        (device_id, scan_id, json_dumps(snapshot), snapshot_hash),
    )
    if previous:
        previous_data = json_loads(previous["snapshot_json"])
        diff = diff_snapshots(previous_data, snapshot)
        if diff["summary"]["total_changes"] > 0:
            db.execute(
                """
                INSERT INTO snapshot_diffs(device_id, previous_snapshot_id, current_snapshot_id, diff_json)
                VALUES (?, ?, ?, ?)
                """,
                (device_id, previous["id"], current_id, json_dumps(diff)),
            )


def snapshot_from_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "system_info",
        "system_inventory_v2",
        "security_controls",
        "software_inventory",
        "process_inventory",
        "security_eventlog",
        "firewall",
        "updates",
        "antivirus",
        "connected_devices",
    ]
    return {key: evidence[key] for key in keys if key in evidence}


def diff_snapshots(previous: Any, current: Any) -> dict[str, Any]:
    changes: list[dict[str, Any]] = []

    def walk(path: str, before: Any, after: Any) -> None:
        if type(before) is not type(after):
            changes.append({"path": path, "change": "changed", "before": summarize_value(before), "after": summarize_value(after)})
            return
        if isinstance(before, dict):
            for key in sorted(set(before) | set(after)):
                next_path = f"{path}.{key}" if path else str(key)
                if key not in before:
                    changes.append({"path": next_path, "change": "added", "after": summarize_value(after[key])})
                elif key not in after:
                    changes.append({"path": next_path, "change": "removed", "before": summarize_value(before[key])})
                else:
                    walk(next_path, before[key], after[key])
            return
        if isinstance(before, list):
            before_hash = hashlib.sha256(json_dumps(before).encode("utf-8")).hexdigest()
            after_hash = hashlib.sha256(json_dumps(after).encode("utf-8")).hexdigest()
            if before_hash != after_hash:
                changes.append({"path": path, "change": "changed", "before": f"{len(before)} items", "after": f"{len(after)} items"})
            return
        if before != after:
            changes.append({"path": path, "change": "changed", "before": summarize_value(before), "after": summarize_value(after)})

    walk("", previous or {}, current or {})
    return {
        "summary": {
            "total_changes": len(changes),
            "added": len([item for item in changes if item["change"] == "added"]),
            "removed": len([item for item in changes if item["change"] == "removed"]),
            "changed": len([item for item in changes if item["change"] == "changed"]),
        },
        "changes": changes[:300],
    }


def summarize_value(value: Any) -> Any:
    if isinstance(value, list):
        return f"{len(value)} items"
    if isinstance(value, dict):
        return f"{len(value)} keys"
    return value


def build_control_matrix(controls: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    open_controls = {
        finding["control"]
        for finding in findings
        if finding.get("status") != "resolved"
    }
    matrix = []
    for key, label in CONTROL_TABS.items():
        entry = controls.get(key)
        status = control_status(key, entry.get("data") if entry else None, open_controls)
        matrix.append(
            {
                "control": key,
                "label": label,
                "status": status,
                "last_seen": entry.get("created_at") if entry else None,
                "scan_type": entry.get("scan_type") if entry else None,
            }
        )
    return matrix


def control_status(control: str, data: Any, open_controls: set[str]) -> str:
    if data is None:
        return "NOT_AVAILABLE"
    if isinstance(data, dict) and data.get("success") is False:
        return "NOT_AVAILABLE"
    if isinstance(data, dict) and data.get("status") == "not_supported":
        return "NOT_AVAILABLE"
    if isinstance(data, dict) and data.get("status") == "not_configured":
        return "NOT_CONFIGURED"
    if control == "backup" and isinstance(data, dict) and data.get("status") in {"missing", "empty"}:
        return "FAIL"
    if control == "threats" and isinstance(data, dict):
        return "FAIL" if int(data.get("active_threat_count") or 0) > 0 else "PASS"
    if control == "connected_devices" and isinstance(data, dict):
        if int(data.get("unsigned_driver_count") or 0) > 0:
            return "FAIL"
        if int(data.get("usb_storage_count") or 0) > 0 or int(data.get("device_error_count") or 0) > 0:
            return "WARNING"
    if control in open_controls:
        return "FAIL"
    return "PASS"


def json_loads(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return {"raw": str(value)}


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def device_view(row: dict[str, Any]) -> dict[str, Any]:
    row.pop("token", None)
    credential_active = row.pop("credential_active", True)
    last_seen = row.get("last_seen")
    row["agent_status"] = "offline"
    row["agent_status_label"] = "Sin conexion"
    if credential_active in {False, 0, "0"}:
        row["agent_status"] = "disconnected"
        row["agent_status_label"] = "Desconectado"
        return row
    parsed = parse_timestamp(last_seen)
    if parsed and (datetime.now(timezone.utc) - parsed).total_seconds() <= AGENT_ONLINE_WINDOW_SECONDS:
        row["agent_status"] = "online"
        row["agent_status_label"] = "En linea"
    return row


def status_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    controls = {}
    for key in ("timestamp", "agent_version", "system_info", "scan_metadata"):
        if key in evidence:
            controls[key] = evidence[key]
    for key in (
        "firewall",
        "updates",
        "antivirus",
        "backup",
        "connected_devices",
        "system_inventory_v2",
        "security_controls",
        "software_inventory",
        "process_inventory",
        "security_eventlog",
    ):
        if key in evidence:
            controls[key] = evidence[key]
    if "listening_ports" in evidence:
        controls["ports"] = evidence["listening_ports"]
    if "services" in evidence:
        controls["services"] = evidence["services"]
    if "local_administrators" in evidence:
        controls["administrators"] = evidence["local_administrators"]
    return controls


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
