from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

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
            "INSERT INTO scans(device_id, scan_type, status) VALUES (?, ?, 'completed')",
            (payload.device_id, payload.scan_type),
        )
        for control, value in status_evidence(payload.evidence).items():
            db.execute(
                "INSERT INTO evidences(scan_id, device_id, control, result_json) VALUES (?, ?, ?, ?)",
                (scan_id, payload.device_id, f"status_{control}", json_dumps(value)),
            )
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
def agent_tasks(device_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _device_for_token(device_id, authorization)
    with connect() as db:
        rows = db.execute(
            """
            SELECT * FROM tasks
            WHERE device_id = ? AND status IN ('pending', 'delivered')
            ORDER BY created_at
            LIMIT 3
            """,
            (device_id,),
        ).fetchall()
        db.execute(
            "UPDATE tasks SET status='delivered', delivered_at=CURRENT_TIMESTAMP WHERE device_id=? AND status='pending'",
            (device_id,),
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
            "cd C:\\pg2; py -3.12 agent\\windows_agent.py --config agent\\agent_config.render.json --poll-once --max-tasks 3",
        ],
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
        devices = [device_view(dict(row)) for row in db.execute("SELECT * FROM devices ORDER BY last_seen DESC NULLS LAST")]
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


def device_view(row: dict[str, Any]) -> dict[str, Any]:
    row.pop("token", None)
    last_seen = row.get("last_seen")
    row["agent_status"] = "offline"
    row["agent_status_label"] = "Sin conexion"
    parsed = parse_timestamp(last_seen)
    if parsed and (datetime.now(timezone.utc) - parsed).total_seconds() <= AGENT_ONLINE_WINDOW_SECONDS:
        row["agent_status"] = "online"
        row["agent_status_label"] = "En linea"
    return row


def status_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    controls = {}
    for key in ("firewall", "updates", "antivirus", "backup", "connected_devices"):
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
