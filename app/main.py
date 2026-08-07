from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .rules import evaluate_rules
from .storage import connect, generate_token, init_db, insert_returning_id, json_dumps

ALLOWED_TASKS = {
    "FULL_SCAN",
    "VERIFY_FIREWALL",
    "VERIFY_PORTS",
    "VERIFY_SERVICES",
    "VERIFY_ADMINISTRATORS",
    "VERIFY_UPDATES",
    "VERIFY_ANTIVIRUS",
    "VERIFY_BACKUP",
}

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SESSION_COOKIE = "cybercheck_session"
SESSION_MAX_AGE = 60 * 60 * 8

app = FastAPI(title="CyberCheck MIPYME", version="1.0.0")


class RegisterRequest(BaseModel):
    company_name: str = Field(min_length=2)
    device_id: str = Field(min_length=2)
    device_name: str = Field(min_length=2)
    os_version: str | None = None
    architecture: str | None = None
    ip_address: str | None = None


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


def _device_for_token(device_id: str, token: str | None) -> dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    token = token.removeprefix("Bearer ").strip()
    with connect() as db:
        row = db.execute("SELECT * FROM devices WHERE device_id = ? AND token = ?", (device_id, token)).fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Token invalido para el equipo")
        return dict(row)


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
    with connect() as db:
        company = db.execute("SELECT id FROM companies WHERE name = ?", (payload.company_name,)).fetchone()
        company_id = company["id"] if company else insert_returning_id(
            db, "INSERT INTO companies(name) VALUES (?)", (payload.company_name,)
        )
        existing = db.execute("SELECT token FROM devices WHERE device_id = ?", (payload.device_id,)).fetchone()
        token = existing["token"] if existing else generate_token()
        db.execute(
            """
            INSERT INTO devices(device_id, company_id, name, os_version, architecture, ip_address, token)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                company_id=excluded.company_id,
                name=excluded.name,
                os_version=excluded.os_version,
                architecture=excluded.architecture,
                ip_address=excluded.ip_address,
                last_seen=CURRENT_TIMESTAMP
            """,
            (
                payload.device_id,
                company_id,
                payload.device_name,
                payload.os_version,
                payload.architecture,
                payload.ip_address,
                token,
            ),
        )
        return {"device_id": payload.device_id, "token": token}


@app.post("/api/agent/results")
def receive_results(payload: ScanRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _device_for_token(payload.device_id, authorization)
    if payload.scan_type not in ALLOWED_TASKS:
        raise HTTPException(status_code=400, detail="Tipo de tarea no permitido")

    rule_results = evaluate_rules(payload.evidence)
    with connect() as db:
        db.execute("UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE device_id = ?", (payload.device_id,))
        scan_id = insert_returning_id(
            db,
            "INSERT INTO scans(device_id, scan_type, status) VALUES (?, ?, 'completed')",
            (payload.device_id, payload.scan_type),
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
            "SELECT * FROM tasks WHERE device_id = ? AND status = 'pending' ORDER BY created_at",
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


@app.post("/api/agent/tasks/{task_id}/complete")
def complete_task(task_id: int, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    body = None
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Tarea no existe")
        _device_for_token(task["device_id"], authorization)
        db.execute("UPDATE tasks SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?", (task_id,))
        return {"status": "completed"}


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        evidences = [dict(row) for row in db.execute("SELECT * FROM evidences ORDER BY created_at DESC LIMIT 120")]
        return {
            "devices": [dict(row) for row in db.execute("SELECT * FROM devices ORDER BY last_seen DESC NULLS LAST")],
            "findings": [dict(row) for row in db.execute("SELECT * FROM findings ORDER BY updated_at DESC")],
            "evidences": evidences,
            "scans": [dict(row) for row in db.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 20")],
            "tasks": [dict(row) for row in db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 20")],
            "history": [dict(row) for row in db.execute("SELECT * FROM history ORDER BY created_at DESC LIMIT 40")],
        }
