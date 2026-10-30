from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import logging
import os
import re
from pathlib import Path
import secrets
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .accounts import (
    ROLE_LABELS,
    audit,
    burn_password_check,
    hash_password,
    public_user,
    role_allows,
    validate_password,
    validate_email,
    validate_role,
    validate_username,
    verify_password,
)
from . import alerts, vulndb
from . import kev as kev_catalog
from . import msrc as msrc_catalog
from . import fixes
from . import plain as plain_language
from .ai_service import answer_company_question, answer_device_question, company_ai_summary, device_ai_summary
from .rules import evaluate_rules
from .storage import connect, generate_device_id, generate_token, hash_agent_token, init_db, insert_returning_id, json_dumps

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
    "VERIFY_HARDENING",
}

# Weight of each open finding against a 100-point device score.
SEVERITY_WEIGHTS = {"critico": 25, "critical": 25, "alto": 10, "high": 10, "medio": 4, "medium": 4, "bajo": 1, "low": 1}
MODULE_LABELS = {
    "firewall": "Firewall", "ports": "Puertos", "services": "Servicios", "administrators": "Administradores",
    "updates": "Windows Update", "antivirus": "Antivirus", "connected_devices": "Dispositivos",
    "backup": "Respaldos", "system_inventory_v2": "Inventario", "security_controls": "Controles de seguridad",
    "software_inventory": "Programas", "process_inventory": "Procesos", "security_eventlog": "Registro de eventos",
    "hardening": "Endurecimiento", "security_detections": "Detecciones",
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
    "hardening": "Endurecimiento",
    "security_detections": "Detecciones de ataques",
    "vulnerabilities": "Vulnerabilidades CVE",
}

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SESSION_COOKIE = "cybercheck_session"
SESSION_MAX_AGE = 60 * 60 * 8
AGENT_ONLINE_WINDOW_SECONDS = 10 * 60
REGISTRATION_WINDOW_SECONDS = 15 * 60
REGISTRATION_ATTEMPT_LIMIT = 20
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_ATTEMPT_LIMIT = 10
TASK_LEASE_SECONDS = 45 * 60
CREDENTIAL_MAX_AGE_DAYS = int(os.getenv("AGENT_CREDENTIAL_MAX_AGE_DAYS", "90"))
CREDENTIAL_GRACE_SECONDS = 24 * 60 * 60
SIGNUP_ATTEMPT_LIMIT = 5
PASSWORD_RESET_LIMIT = 5
PASSWORD_RESET_SECONDS = 60 * 60
OFFLINE_ALERT_HOURS = int(os.getenv("OFFLINE_ALERT_HOURS", "48"))
OFFLINE_CHECK_SECONDS = 10 * 60
ENROLLMENT_TOKEN_DAYS = 30
INSTALLER_CACHE_SECONDS = 60 * 60
DEFAULT_RELEASES_REPO = "jacob11-byte/plataforma-ciberseguridad-mipymes"
DEFAULT_INSTALLER_URL = (
    f"https://github.com/{DEFAULT_RELEASES_REPO}/releases/latest/download/CyberCheckSetup.exe"
)
_DEV_SESSION_SECRET = secrets.token_urlsafe(48)

app = FastAPI(title="CyberCheck MIPYME", version="1.0.0")


class RegisterRequest(BaseModel):
    registration_code: str = Field(min_length=4, max_length=256)
    company_name: str = Field(default="MIPYME Principal", min_length=2, max_length=120)
    hostname: str = Field(min_length=1, max_length=255)
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
    request_id: str | None = Field(default=None, min_length=8, max_length=128)
    task_id: int | None = Field(default=None, ge=1)


class TaskRequest(BaseModel):
    device_id: str
    task_type: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class TaskFailureRequest(BaseModel):
    error: str | None = Field(default=None, max_length=500)


class LoginRequest(BaseModel):
    username: str
    password: str


class AiChatRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)


class AgentEvent(BaseModel):
    event_key: str = Field(min_length=4, max_length=128)
    event_type: str = Field(min_length=1, max_length=60)
    severity: str = Field(pattern="^(Critico|Alto|Medio|Bajo|Info)$")
    title: str = Field(min_length=1, max_length=200)
    detail: str = Field(default="", max_length=1000)
    occurred_at: str = Field(min_length=10, max_length=40)
    data: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    device_id: str
    events: list[AgentEvent] = Field(min_length=1, max_length=100)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=160)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=1, max_length=256)


class SignupRequest(BaseModel):
    company_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=160)
    password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: str = "viewer"


class UserUpdateRequest(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


class CredentialRotationRequest(BaseModel):
    device_id: str


@app.on_event("startup")
def startup() -> None:
    validate_security_config()
    init_db()
    with connect() as db:
        default_company = _default_company_id(db)
        # Users created before multi-tenancy belong to the original company.
        db.execute("UPDATE users SET company_id=? WHERE company_id IS NULL", (default_company,))
    start_offline_watcher()
    kev_catalog.start_refresher()
    msrc_catalog.start_refresher()


def _production_mode() -> bool:
    return os.getenv("CYBERCHECK_ENV", "").strip().lower() in {"prod", "production"} or bool(
        os.getenv("RENDER_SERVICE_ID") or os.getenv("RENDER")
    )


def validate_security_config() -> None:
    """Fail closed before serving requests with an unsafe production configuration."""
    if not _production_mode():
        return
    required = {
        "ADMIN_PASSWORD": 12,
        "SESSION_SECRET": 32,
        "AGENT_REGISTRATION_CODE": 24,
    }
    for name, minimum in required.items():
        value = os.getenv(name, "")
        if len(value) < minimum:
            raise RuntimeError(f"{name} debe tener al menos {minimum} caracteres en produccion")
    if os.environ["ADMIN_PASSWORD"] in {"admin123", "password", "changeme"}:
        raise RuntimeError("ADMIN_PASSWORD no puede usar una contrasena de ejemplo")
    if os.environ["SESSION_SECRET"] in {os.environ["ADMIN_PASSWORD"], os.environ["AGENT_REGISTRATION_CODE"]}:
        raise RuntimeError("SESSION_SECRET debe ser independiente de las otras credenciales")
    if not os.getenv("DATABASE_URL"):
        raise RuntimeError("DATABASE_URL (PostgreSQL) es obligatorio en produccion")
    if os.getenv("COOKIE_SECURE", "true").lower() == "false":
        raise RuntimeError("COOKIE_SECURE no puede deshabilitarse en produccion")


def _setting(name: str, development_default: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    if _production_mode():
        raise RuntimeError(f"{name} es obligatorio en produccion")
    return development_default


def _admin_username() -> str:
    return os.getenv("ADMIN_USERNAME", "admin")


def _admin_password() -> str:
    return _setting("ADMIN_PASSWORD", "admin123")


def _session_secret() -> str:
    return _setting("SESSION_SECRET", _DEV_SESSION_SECRET)


def _sign(value: str) -> str:
    signature = hmac.new(_session_secret().encode("utf-8"), value.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _create_session(username: str, epoch: int = 0) -> str:
    expires = str(int(time.time()) + SESSION_MAX_AGE)
    nonce = secrets.token_urlsafe(12)
    payload = f"{username}|{expires}|{nonce}|{epoch}"
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{token}.{_sign(token)}"


def _session_user(request: Request) -> dict[str, Any] | None:
    """Return the signed-in user with its current role, or None.

    The role is read from the database on every request so that disabling a
    user or changing its role takes effect immediately; ``session_epoch``
    invalidates cookies issued before a password or role change.
    """
    cached = getattr(request.state, "user", None)
    if cached:
        return cached
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie or "." not in cookie:
        return None
    token, signature = cookie.rsplit(".", 1)
    if not hmac.compare_digest(signature, _sign(token)):
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        payload = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        username, expires, _nonce, epoch = payload.split("|", 3)
        expiry = int(expires)
        session_epoch = int(epoch)
    except (ValueError, UnicodeDecodeError, binascii.Error, OverflowError):
        return None
    if expiry < int(time.time()):
        return None
    if hmac.compare_digest(username, _admin_username()):
        with connect() as db:
            company_id = _default_company_id(db)
        user = {"username": username, "role": "admin", "bootstrap": True, "company_id": company_id}
    else:
        with connect() as db:
            row = db.execute(
                "SELECT username, role, active, session_epoch, company_id FROM users WHERE username=?",
                (username,),
            ).fetchone()
        if (
            not row
            or row["active"] in {False, 0, "0"}
            or int(row["session_epoch"]) != session_epoch
            or row["company_id"] is None
        ):
            return None
        user = {
            "username": row["username"],
            "role": row["role"],
            "bootstrap": False,
            "company_id": int(row["company_id"]),
        }
    request.state.user = user
    return user


def _default_company_name() -> str:
    return os.getenv("DEFAULT_COMPANY_NAME", "MIPYME Principal")


def _default_company_id(db: Any) -> int:
    """Company of the bootstrap admin and of agents enrolled with the global code."""
    row = db.execute(
        "SELECT id FROM companies WHERE name=? ORDER BY id LIMIT 1", (_default_company_name(),)
    ).fetchone()
    if row:
        return int(row["id"])
    return insert_returning_id(db, "INSERT INTO companies(name) VALUES (?)", (_default_company_name(),))


def _company_id(request: Request) -> int:
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sesion requerida")
    return int(user["company_id"])


def _company_device(db: Any, device_id: str, company_id: int) -> dict[str, Any]:
    """Load a device only if it belongs to the caller's company.

    Devices of other tenants answer 404, never 403, so their IDs cannot be probed.
    """
    row = db.execute(
        "SELECT * FROM devices WHERE device_id=? AND company_id=?", (device_id, company_id)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Equipo no existe")
    return dict(row)


def _read_session(request: Request) -> str | None:
    user = _session_user(request)
    return user["username"] if user else None


def _client_hash(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    return hashlib.sha256(client_host.encode("utf-8")).hexdigest()[:16]


def _actor(request: Request) -> str:
    user = _session_user(request)
    return user["username"] if user else "anonymous"


def _require_same_origin(request: Request) -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise HTTPException(status_code=403, detail="Origen no autorizado")
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        if _production_mode():
            raise HTTPException(status_code=403, detail="Encabezado Origin o Referer requerido")
        return
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != request.headers.get("host", "").lower():
        raise HTTPException(status_code=403, detail="Origen no autorizado")


def _require_user(request: Request, role: str = "viewer") -> str:
    user = _session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sesion requerida")
    _require_same_origin(request)
    if not role_allows(user["role"], role):
        raise HTTPException(status_code=403, detail="Tu rol no permite esta accion")
    return user["username"]


def _registration_code() -> str:
    return _setting("AGENT_REGISTRATION_CODE", "cybercheck-register-dev")


def _check_registration_limit(request: Request) -> None:
    client_host = request.client.host if request.client else "unknown"
    client_hash = hashlib.sha256(client_host.encode("utf-8")).hexdigest()
    now = int(time.time())
    expired_before = now - REGISTRATION_WINDOW_SECONDS
    with connect() as db:
        db.execute(
            """
            INSERT INTO registration_rate_limits(client_hash, window_started, attempts)
            VALUES (?, ?, 1)
            ON CONFLICT(client_hash) DO UPDATE SET
                window_started = CASE WHEN registration_rate_limits.window_started < ?
                    THEN excluded.window_started ELSE registration_rate_limits.window_started END,
                attempts = CASE WHEN registration_rate_limits.window_started < ?
                    THEN 1 ELSE registration_rate_limits.attempts + 1 END
            """,
            (client_hash, now, expired_before, expired_before),
        )
        row = db.execute("SELECT attempts, window_started FROM registration_rate_limits WHERE client_hash = ?", (client_hash,)).fetchone()
    if row["attempts"] > REGISTRATION_ATTEMPT_LIMIT:
        retry_after = max(1, REGISTRATION_WINDOW_SECONDS - (now - int(row["window_started"])))
        raise HTTPException(status_code=429, detail="Demasiados intentos de registro", headers={"Retry-After": str(retry_after)})


def _login_client_hash(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    return hashlib.sha256(client_host.encode("utf-8")).hexdigest()


def _check_login_limit(request: Request) -> str:
    client_hash = _login_client_hash(request)
    now = int(time.time())
    expired_before = now - LOGIN_WINDOW_SECONDS
    with connect() as db:
        db.execute(
            """
            INSERT INTO login_rate_limits(client_hash, window_started, attempts)
            VALUES (?, ?, 1)
            ON CONFLICT(client_hash) DO UPDATE SET
                window_started = CASE WHEN login_rate_limits.window_started < ?
                    THEN excluded.window_started ELSE login_rate_limits.window_started END,
                attempts = CASE WHEN login_rate_limits.window_started < ?
                    THEN 1 ELSE login_rate_limits.attempts + 1 END
            """,
            (client_hash, now, expired_before, expired_before),
        )
        row = db.execute(
            "SELECT attempts, window_started FROM login_rate_limits WHERE client_hash=?", (client_hash,)
        ).fetchone()
    if row["attempts"] > LOGIN_ATTEMPT_LIMIT:
        retry_after = max(1, LOGIN_WINDOW_SECONDS - (now - int(row["window_started"])))
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos de inicio de sesion",
            headers={"Retry-After": str(retry_after)},
        )
    return client_hash


def _clear_login_limit(client_hash: str) -> None:
    with connect() as db:
        db.execute("DELETE FROM login_rate_limits WHERE client_hash=?", (client_hash,))


def _device_for_token(device_id: str, token: str | None) -> dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="Token requerido")
    scheme, separator, credential = token.partition(" ")
    if not separator or scheme.lower() != "bearer" or not credential.strip():
        raise HTTPException(status_code=401, detail="Token Bearer requerido")
    token_hash = hash_agent_token(credential.strip())
    with connect() as db:
        now_value = _db_time(db, datetime.now(timezone.utc))
        row = db.execute(
            """
            SELECT d.*, c.id AS credential_id, c.expires_at AS credential_expires_at,
                c.created_at AS credential_created_at
            FROM devices d
            JOIN agent_credentials c ON c.device_id = d.device_id
            WHERE d.device_id = ? AND c.token = ? AND c.active = ?
                AND (c.expires_at IS NULL OR c.expires_at > ?)
            """,
            (device_id, token_hash, True, now_value),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=403, detail="Token invalido para el equipo")
        db.execute("UPDATE agent_credentials SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", (row["credential_id"],))
        if row["credential_expires_at"] is None:
            # First use of a rotated credential: older credentials of this
            # device were only kept alive as a grace period, retire them now.
            retired = db.execute(
                """
                UPDATE agent_credentials SET active=?
                WHERE device_id=? AND id<>? AND active=? AND expires_at IS NOT NULL
                """,
                (False, device_id, row["credential_id"], True),
            )
            if retired.rowcount:
                db.execute(
                    "UPDATE devices SET credential_rotation_requested=? WHERE device_id=?",
                    (False, device_id),
                )
        return dict(row)


def _db_time(db: Any, value: datetime) -> Any:
    return value if db.is_postgres else value.strftime("%Y-%m-%d %H:%M:%S")


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


@app.get("/devices/{device_id}/report")
def device_report_page(device_id: str, request: Request):
    if not _read_session(request):
        return RedirectResponse("/login", status_code=302)
    return FileResponse(WEB_DIR / "report.html")


@app.get("/reset")
def reset_page() -> FileResponse:
    return FileResponse(WEB_DIR / "reset.html")


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


@app.get("/static/modules/{filename}")
def module_script(filename: str) -> FileResponse:
    if "/" in filename or "\\" in filename or not filename.endswith(".js"):
        raise HTTPException(status_code=404, detail="Modulo no encontrado")
    path = WEB_DIR / "modules" / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Modulo no encontrado")
    return FileResponse(path, media_type="application/javascript")


@app.get("/static/device.js")
def device_script() -> FileResponse:
    return FileResponse(WEB_DIR / "device.js", media_type="application/javascript")


@app.post("/api/login")
def login(payload: LoginRequest, request: Request) -> JSONResponse:
    if _production_mode():
        validate_security_config()
    client_hash = _check_login_limit(request)
    source = client_hash[:16]
    role: str | None = None
    epoch = 0
    username = payload.username.strip()
    company_id: int | None = None
    if hmac.compare_digest(username, _admin_username()):
        if hmac.compare_digest(payload.password, _admin_password()):
            role = "admin"
            with connect() as db:
                company_id = _default_company_id(db)
    else:
        with connect() as db:
            row = db.execute(
                """
                SELECT id, username, role, active, password_hash, session_epoch, company_id
                FROM users WHERE lower(username)=lower(?)
                """,
                (username,),
            ).fetchone()
        if row is None:
            burn_password_check(payload.password)
        elif verify_password(payload.password, row["password_hash"]) and row["active"] not in {False, 0, "0"}:
            role = row["role"]
            epoch = int(row["session_epoch"])
            username = row["username"]
            company_id = row["company_id"]
            with connect() as db:
                db.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?", (row["id"],))
    if role is None:
        with connect() as db:
            audit(db, username[:64] or "?", "login.failure", source=source)
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    _clear_login_limit(client_hash)
    with connect() as db:
        audit(db, username, "login.success", details={"role": role}, source=source, company_id=company_id)
    return _session_response({"ok": True, "username": username, "role": role}, username, epoch)


def _session_response(body: dict[str, Any], username: str, epoch: int) -> JSONResponse:
    response = JSONResponse(body)
    _set_session_cookie(response, username, epoch)
    return response


def _set_session_cookie(response: Response, username: str, epoch: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        _create_session(username, epoch),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=_production_mode() or os.getenv("COOKIE_SECURE", "true").lower() != "false",
        samesite="strict",
    )


@app.post("/api/logout")
def logout(request: Request) -> Response:
    username = _require_user(request)
    with connect() as db:
        audit(db, username, "logout", source=_client_hash(request), company_id=_company_id(request))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/me")
def me(request: Request) -> dict[str, Any]:
    _require_user(request)
    user = _session_user(request) or {}
    with connect() as db:
        company = db.execute("SELECT name FROM companies WHERE id=?", (user.get("company_id"),)).fetchone()
    return {
        "username": user.get("username"),
        "role": user.get("role"),
        "role_label": ROLE_LABELS.get(user.get("role", ""), user.get("role")),
        "bootstrap": user.get("bootstrap", False),
        "company_name": company["name"] if company else None,
    }


@app.get("/api/auth/providers")
def auth_providers() -> dict[str, Any]:
    return {"google": _google_enabled(), "signup": _signup_enabled(), "reset": alerts.smtp_configured()}


@app.post("/api/password/forgot")
def password_forgot(payload: ForgotPasswordRequest, request: Request) -> dict[str, Any]:
    """Always answers the same way so it cannot be used to discover accounts."""
    generic = {"ok": True, "message": "Si el correo tiene una cuenta, enviamos un enlace para restablecer la contrasena."}
    if not alerts.smtp_configured():
        raise HTTPException(status_code=503, detail="La recuperacion por correo no esta configurada; contacta al administrador")
    _check_hourly_limit(request, "forgot", PASSWORD_RESET_LIMIT, "Demasiadas solicitudes; intenta mas tarde")
    email = payload.email.strip().lower()
    with connect() as db:
        user = db.execute(
            "SELECT id, username FROM users WHERE lower(username)=? AND active=?", (email, True)
        ).fetchone()
        if user and "@" in user["username"]:
            token = secrets.token_urlsafe(32)
            expires = _db_time(db, datetime.now(timezone.utc) + timedelta(seconds=PASSWORD_RESET_SECONDS))
            db.execute(
                "INSERT INTO password_resets(user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user["id"], hash_agent_token(token), expires),
            )
            audit(db, user["username"], "password.reset_requested", source=_client_hash(request))
            alerts.send_password_reset(user["username"], f"{_public_base_url(request)}/reset?token={token}")
    return generic


@app.post("/api/password/reset")
def password_reset(payload: ResetPasswordRequest, request: Request) -> dict[str, Any]:
    try:
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _check_hourly_limit(request, "reset", PASSWORD_RESET_LIMIT * 4, "Demasiados intentos; intenta mas tarde")
    with connect() as db:
        row = db.execute(
            """
            SELECT r.id, r.user_id, u.username, u.company_id FROM password_resets r
            JOIN users u ON u.id = r.user_id
            WHERE r.token_hash=? AND r.used=? AND r.expires_at > ? AND u.active=?
            """,
            (hash_agent_token(payload.token), False, _db_time(db, datetime.now(timezone.utc)), True),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="El enlace no es valido o ya expiro; solicita uno nuevo")
        db.execute("UPDATE password_resets SET used=? WHERE id=?", (True, row["id"]))
        # A new password also closes every session opened with the old one.
        db.execute(
            "UPDATE users SET password_hash=?, session_epoch=session_epoch+1, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (hash_password(payload.password), row["user_id"]),
        )
        audit(db, row["username"], "password.reset", source=_client_hash(request), company_id=row["company_id"])
    return {"ok": True}


def _signup_enabled() -> bool:
    return os.getenv("SIGNUP_ENABLED", "true").strip().lower() not in {"0", "false", "no"}


def _check_signup_limit(request: Request) -> None:
    _check_hourly_limit(
        request, "signup", SIGNUP_ATTEMPT_LIMIT, "Demasiadas cuentas creadas desde esta red; intenta mas tarde"
    )


def _check_hourly_limit(request: Request, scope: str, limit: int, detail: str) -> None:
    """Per-address hourly limiter; shares the login limiter table."""
    key = f"{scope}:" + _login_client_hash(request)
    now = int(time.time())
    window = 60 * 60
    with connect() as db:
        db.execute(
            """
            INSERT INTO login_rate_limits(client_hash, window_started, attempts)
            VALUES (?, ?, 1)
            ON CONFLICT(client_hash) DO UPDATE SET
                window_started = CASE WHEN login_rate_limits.window_started < ?
                    THEN excluded.window_started ELSE login_rate_limits.window_started END,
                attempts = CASE WHEN login_rate_limits.window_started < ?
                    THEN 1 ELSE login_rate_limits.attempts + 1 END
            """,
            (key, now, now - window, now - window),
        )
        row = db.execute("SELECT attempts FROM login_rate_limits WHERE client_hash=?", (key,)).fetchone()
    if row["attempts"] > limit:
        raise HTTPException(status_code=429, detail=detail)


def _create_account(db: Any, email: str, company_name: str, password_hash: str | None, provider: str) -> int:
    """Create an isolated company with ``email`` as its first administrator."""
    company_id = insert_returning_id(db, "INSERT INTO companies(name) VALUES (?)", (company_name,))
    insert_returning_id(
        db,
        "INSERT INTO users(company_id, username, role, password_hash) VALUES (?, ?, 'admin', ?)",
        (company_id, email, password_hash),
    )
    audit(db, email, "account.signup", target_type="company", target_id=company_id,
          details={"company": company_name, "provider": provider}, company_id=company_id)
    return company_id


@app.post("/api/signup")
def signup(payload: SignupRequest, request: Request) -> JSONResponse:
    if not _signup_enabled():
        raise HTTPException(status_code=403, detail="El registro de cuentas esta deshabilitado")
    try:
        email = validate_email(payload.email)
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    company_name = payload.company_name.strip()
    if len(company_name) < 2:
        raise HTTPException(status_code=400, detail="Escribe el nombre de tu empresa")
    if email == _admin_username().lower():
        raise HTTPException(status_code=409, detail="Ese correo ya tiene una cuenta")
    _check_signup_limit(request)
    with connect() as db:
        if db.execute("SELECT id FROM users WHERE lower(username)=?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="Ese correo ya tiene una cuenta; inicia sesion")
        _create_account(db, email, company_name, hash_password(payload.password), "password")
    return _session_response({"ok": True, "username": email, "role": "admin"}, email, 0)


# --- Google sign-in (OpenID Connect, authorization code flow) ---------------------

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
OAUTH_STATE_COOKIE = "cybercheck_oauth_state"


def _google_enabled() -> bool:
    return bool(os.getenv("GOOGLE_CLIENT_ID") and os.getenv("GOOGLE_CLIENT_SECRET"))


def _public_base_url(request: Request) -> str:
    configured = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    base = str(request.base_url).rstrip("/")
    # Render terminates TLS at its proxy, so the app itself sees http://.
    if _production_mode() and base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


def _google_redirect_uri(request: Request) -> str:
    return f"{_public_base_url(request)}/auth/google/callback"


def _login_error_redirect(message: str) -> RedirectResponse:
    return RedirectResponse(f"/login?error={quote(message)}", status_code=302)


@app.get("/auth/google/start")
def google_start(request: Request) -> Response:
    if not _google_enabled():
        return _login_error_redirect("El inicio con Google no esta configurado")
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": _google_redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    response = RedirectResponse(f"{GOOGLE_AUTH_URL}?{urlencode(params)}", status_code=302)
    # Lax (not Strict) so the cookie survives Google's top-level redirect back.
    response.set_cookie(
        OAUTH_STATE_COOKIE, state, max_age=600, httponly=True, samesite="lax",
        secure=_production_mode() or os.getenv("COOKIE_SECURE", "true").lower() != "false",
    )
    return response


def _google_profile(code: str, redirect_uri: str) -> dict[str, Any]:
    with httpx.Client(timeout=15) as client:
        token_response = client.post(GOOGLE_TOKEN_URL, data={
            "code": code,
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        profile = client.get(GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
        profile.raise_for_status()
        return profile.json()


@app.get("/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = "", error: str = "") -> Response:
    expected_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
    if error or not code or not state or not expected_state or not hmac.compare_digest(state, expected_state):
        return _login_error_redirect("No se pudo completar el inicio con Google")
    try:
        profile = _google_profile(code, _google_redirect_uri(request))
        email = validate_email(str(profile.get("email", "")))
    except (httpx.HTTPError, KeyError, ValueError):
        return _login_error_redirect("Google no confirmo tu cuenta; intenta de nuevo")
    if profile.get("email_verified") is not True:
        return _login_error_redirect("Tu correo de Google no esta verificado")
    with connect() as db:
        row = db.execute(
            "SELECT username, active, session_epoch, company_id FROM users WHERE lower(username)=?", (email,)
        ).fetchone()
        if row and row["active"] in {False, 0, "0"}:
            return _login_error_redirect("Tu usuario esta desactivado")
        if row:
            username, epoch, company_id = row["username"], int(row["session_epoch"]), row["company_id"]
            db.execute("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE lower(username)=?", (email,))
        else:
            if not _signup_enabled():
                return _login_error_redirect("No existe una cuenta para ese correo")
            name = str(profile.get("name") or email.split("@", 1)[0]).strip()[:80]
            username, epoch = email, 0
            company_id = _create_account(db, email, f"Empresa de {name}", None, "google")
        audit(db, username, "login.success", details={"provider": "google"},
              source=_client_hash(request), company_id=company_id)
    # A same-origin page performs the final navigation so the SameSite=Strict
    # session cookie is sent (a redirect chain started by Google would drop it).
    response = Response(
        '<!doctype html><meta charset="utf-8"><title>CyberCheck</title>'
        '<script>window.location.replace("/")</script>'
        '<noscript><a href="/">Continuar</a></noscript>',
        media_type="text/html",
    )
    _set_session_cookie(response, username, epoch)
    response.delete_cookie(OAUTH_STATE_COOKIE)
    return response


@app.get("/api/users")
def list_users(request: Request) -> dict[str, Any]:
    _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        rows = db.execute(
            """
            SELECT id, username, role, active, last_login_at, created_at, updated_at
            FROM users WHERE company_id=? ORDER BY username
            """,
            (company_id,),
        ).fetchall()
    user = _session_user(request) or {}
    return {
        "bootstrap_admin": _admin_username() if user.get("bootstrap") else None,
        "users": [public_user(row) for row in rows],
        "roles": ROLE_LABELS,
    }


@app.post("/api/users")
def create_user(payload: UserCreateRequest, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    try:
        username = validate_username(payload.username)
        role = validate_role(payload.role)
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if username.lower() == _admin_username().lower():
        raise HTTPException(status_code=409, detail="Ese nombre esta reservado para el administrador inicial")
    with connect() as db:
        if db.execute("SELECT id FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
            raise HTTPException(status_code=409, detail="El usuario ya existe")
        user_id = insert_returning_id(
            db,
            "INSERT INTO users(company_id, username, role, password_hash) VALUES (?, ?, ?, ?)",
            (company_id, username, role, hash_password(payload.password)),
        )
        audit(db, actor, "user.create", target_type="user", target_id=username,
              details={"role": role}, source=_client_hash(request), company_id=company_id)
        row = db.execute(
            "SELECT id, username, role, active, last_login_at, created_at, updated_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
    return public_user(row)


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, payload: UserUpdateRequest, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    changes: dict[str, Any] = {}
    try:
        if payload.role is not None:
            changes["role"] = validate_role(payload.role)
        if payload.password is not None:
            validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if payload.active is not None:
        changes["active"] = payload.active
    if not changes and payload.password is None:
        raise HTTPException(status_code=400, detail="No hay cambios")
    with connect() as db:
        row = db.execute(
            "SELECT id, username FROM users WHERE id=? AND company_id=?", (user_id, company_id)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuario no existe")
        if row["username"] == actor and (changes.get("active") is False or changes.get("role", "admin") != "admin"):
            raise HTTPException(status_code=409, detail="No puedes quitarte tu propio acceso de administrador")
        assignments = [f"{column}=?" for column in changes]
        values = list(changes.values())
        if payload.password is not None:
            assignments.append("password_hash=?")
            values.append(hash_password(payload.password))
        # Any change to credentials or privileges invalidates open sessions.
        assignments += ["session_epoch=session_epoch+1", "updated_at=CURRENT_TIMESTAMP"]
        db.execute(f"UPDATE users SET {', '.join(assignments)} WHERE id=?", (*values, user_id))
        audit(db, actor, "user.update", target_type="user", target_id=row["username"],
              details={**changes, "password_changed": payload.password is not None},
              source=_client_hash(request), company_id=company_id)
        updated = db.execute(
            "SELECT id, username, role, active, last_login_at, created_at, updated_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
    return public_user(updated)


@app.get("/api/audit")
def audit_log(request: Request, limit: int = Query(default=200, ge=1, le=1000)) -> dict[str, Any]:
    _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        rows = db.execute(
            """
            SELECT id, actor, action, target_type, target_id, details_json, created_at
            FROM admin_audit_log WHERE company_id=? ORDER BY id DESC LIMIT ?
            """,
            (company_id, limit),
        ).fetchall()
    return {"events": [{**dict(row), "details": json_loads(row["details_json"])} for row in rows]}


# --- Agent enrollment ---------------------------------------------------------------

def _issue_enrollment_token(db: Any, company_id: int, actor: str) -> str:
    """Short-lived, company-bound secret embedded in a downloaded installer."""
    token = secrets.token_hex(16)
    expires = _db_time(db, datetime.now(timezone.utc) + timedelta(days=ENROLLMENT_TOKEN_DAYS))
    db.execute(
        "INSERT INTO enrollment_tokens(company_id, token_hash, created_by, expires_at) VALUES (?, ?, ?, ?)",
        (company_id, hash_agent_token(token), actor, expires),
    )
    return token


def _enrollment_company(db: Any, code: str) -> int | None:
    """Company for a registration code: an enrollment token or the global code."""
    row = db.execute(
        """
        SELECT id, company_id FROM enrollment_tokens
        WHERE token_hash=? AND revoked=0 AND expires_at > ?
        """,
        (hash_agent_token(code.strip()), _db_time(db, datetime.now(timezone.utc))),
    ).fetchone()
    if row:
        db.execute("UPDATE enrollment_tokens SET uses=uses+1 WHERE id=?", (row["id"],))
        return int(row["company_id"])
    if hmac.compare_digest(code.strip(), _registration_code().strip()):
        # The global code is the bootstrap tenant's; it never picks a company
        # by name, so it cannot be used to plant devices in another account.
        return _default_company_id(db)
    return None


RELEASE_CHECK_SECONDS = 60 * 60
RELEASE_FAILURE_RETRY_SECONDS = 10 * 60
_release_cache: dict[str, Any] = {"checked": 0.0, "info": None}


def version_tuple(value: Any) -> tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value or ""))[:4]]
    return tuple(parts) or (0,)


def _latest_release() -> dict[str, Any] | None:
    """Newest published agent ({version, url}), from GitHub Releases, cached."""
    if os.getenv("AGENT_INSTALLER_PATH"):
        version = os.getenv("LATEST_AGENT_VERSION")
        return {"version": version, "url": None} if version else None
    repo = os.getenv("AGENT_RELEASES_REPO", DEFAULT_RELEASES_REPO)
    now = time.time()
    age = now - _release_cache["checked"]
    if age < (RELEASE_CHECK_SECONDS if _release_cache["info"] else RELEASE_FAILURE_RETRY_SECONDS):
        return _release_cache["info"]
    _release_cache["checked"] = now
    try:
        response = httpx.get(f"https://api.github.com/repos/{repo}/releases/latest",
                             headers={"Accept": "application/vnd.github+json"}, timeout=15)
        response.raise_for_status()
        data = response.json()
        asset = next(item for item in data["assets"] if item["name"] == "CyberCheckSetup.exe")
        _release_cache["info"] = {
            "version": str(data["tag_name"]).removeprefix("agent-v"),
            "url": asset["browser_download_url"],
        }
    except (httpx.HTTPError, ValueError, KeyError, StopIteration):
        logging.getLogger("cybercheck.update").warning("No se pudo consultar la ultima version del agente")
    return _release_cache["info"]


def _sha256_of(path: Path) -> str:
    sidecar = path.with_name(path.name + ".sha256")
    if sidecar.is_file() and sidecar.stat().st_mtime >= path.stat().st_mtime:
        return sidecar.read_text(encoding="ascii").strip()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    sidecar.write_text(digest.hexdigest(), encoding="ascii")
    return digest.hexdigest()


def _installer_bundle() -> tuple[Path, str, str | None]:
    """(installer path, sha256, version) of the agent the server hands out.

    The file and its version come from the same GitHub release, so an update
    offer can never point at a different build than the one downloaded.
    """
    local = os.getenv("AGENT_INSTALLER_PATH")
    if local and Path(local).is_file():
        return Path(local), _sha256_of(Path(local)), os.getenv("LATEST_AGENT_VERSION")
    release = _latest_release()
    version = release["version"] if release else None
    url = os.getenv("AGENT_INSTALLER_URL") or (release["url"] if release else DEFAULT_INSTALLER_URL)
    cache = Path(tempfile.gettempdir()) / "cybercheck-installer" / f"CyberCheckSetup-{version or 'latest'}.exe"
    fresh = cache.is_file() and (version or time.time() - cache.stat().st_mtime < INSTALLER_CACHE_SECONDS)
    if not fresh:
        cache.parent.mkdir(parents=True, exist_ok=True)
        partial = cache.with_suffix(".part")
        digest = hashlib.sha256()
        with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
            response.raise_for_status()
            with partial.open("wb") as handle:
                for chunk in response.iter_bytes():
                    digest.update(chunk)
                    handle.write(chunk)
        expected = os.getenv("AGENT_INSTALLER_SHA256", "").strip().lower()
        if expected and not hmac.compare_digest(digest.hexdigest(), expected):
            partial.unlink(missing_ok=True)
            raise RuntimeError("El instalador descargado no coincide con AGENT_INSTALLER_SHA256")
        os.replace(partial, cache)
        cache.with_name(cache.name + ".sha256").write_text(digest.hexdigest(), encoding="ascii")
    return cache, _sha256_of(cache), version


def _installer_file() -> Path:
    return _installer_bundle()[0]


def _auto_update_enabled() -> bool:
    configured = os.getenv("AGENT_AUTO_UPDATE")
    if configured is not None:
        return configured.strip().lower() not in {"0", "false", "no", "off"}
    return _production_mode()


def _update_offer(current_version: str) -> dict[str, Any] | None:
    """Tell an outdated agent which build to install, with its SHA-256."""
    if not _auto_update_enabled():
        return None
    release = _latest_release()
    if not release or not release.get("version") or version_tuple(release["version"]) <= version_tuple(current_version):
        return None
    try:
        _path, sha256, version = _installer_bundle()
    except Exception:  # noqa: BLE001 - an unavailable installer just postpones the update
        return None
    if version != release["version"]:
        return None
    return {"version": version, "sha256": sha256, "url": "/api/agent/update"}


@app.get("/api/agent/update")
def agent_update(device_id: str, authorization: str | None = Header(default=None)) -> Response:
    """Installer for the agent's self-update; only enrolled devices get it."""
    _device_for_token(device_id, authorization)
    try:
        path, sha256, version = _installer_bundle()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Actualizacion no disponible") from exc
    return FileResponse(
        path, media_type="application/vnd.microsoft.portable-executable",
        filename=f"CyberCheckSetup-{version or 'latest'}.exe",
        headers={"X-Installer-SHA256": sha256, "Cache-Control": "no-store"},
    )


@app.get("/api/agent/installer")
def download_installer(request: Request) -> Response:
    actor = _require_user(request, "technician")
    company_id = _company_id(request)
    try:
        installer = _installer_file()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="El instalador no esta disponible en este momento") from exc
    with connect() as db:
        token = _issue_enrollment_token(db, company_id, actor)
        audit(db, actor, "installer.download", target_type="company", target_id=company_id,
              source=_client_hash(request), company_id=company_id)
    # The installer reads the enrollment token from its own file name.
    return FileResponse(
        installer,
        media_type="application/vnd.microsoft.portable-executable",
        filename=f"CyberCheckSetup_{token}.exe",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/agent/installer/revoke")
def revoke_installers(request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        revoked = db.execute(
            "UPDATE enrollment_tokens SET revoked=1 WHERE company_id=? AND revoked=0", (company_id,)
        ).rowcount
        audit(db, actor, "installer.revoke", target_type="company", target_id=company_id,
              details={"revoked": revoked}, source=_client_hash(request), company_id=company_id)
    return {"revoked": revoked}


@app.post("/api/register")
def register(payload: RegisterRequest, request: Request) -> dict[str, Any]:
    if _production_mode():
        validate_security_config()
    _check_registration_limit(request)
    with connect() as db:
        company_id = _enrollment_company(db, payload.registration_code)
        if company_id is None:
            raise HTTPException(status_code=403, detail="Codigo de registro invalido")
        device_id = generate_device_id()
        token = generate_token()
        stored_token = hash_agent_token(token)
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
                stored_token,
            ),
        )
        db.execute(
            "INSERT INTO agent_credentials(device_id, token) VALUES (?, ?)",
            (device_id, stored_token),
        )
        audit(db, f"agent:{device_id}", "device.register", target_type="device", target_id=device_id,
              details={"hostname": payload.hostname}, source=_client_hash(request), company_id=company_id)
        return {"device_id": device_id, "token": token, "hostname": payload.hostname}


def _credential_needs_rotation(device: dict[str, Any]) -> bool:
    if device.get("credential_rotation_requested") in {True, 1, "1"}:
        return True
    created = parse_timestamp(device.get("credential_created_at"))
    return bool(created and datetime.now(timezone.utc) - created > timedelta(days=CREDENTIAL_MAX_AGE_DAYS))


@app.post("/api/agent/heartbeat")
def heartbeat(payload: HeartbeatRequest, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    device = _device_for_token(payload.device_id, authorization)
    with connect() as db:
        db.execute(
            "UPDATE devices SET last_seen=CURRENT_TIMESTAMP, agent_version=?, offline_alerted=? WHERE device_id=?",
            (payload.agent_version, False, payload.device_id),
        )
        return {
            "ok": True,
            "device_id": payload.device_id,
            "rotate_credential": _credential_needs_rotation(device),
            "update": _update_offer(payload.agent_version),
        }


@app.post("/api/agent/rotate-credential")
def rotate_agent_credential(
    payload: CredentialRotationRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Issue a new token; the current one stays valid for a grace period.

    The previous credential is retired as soon as the agent authenticates
    with the new token, so a lost response or a failed config write never
    locks the device out.
    """
    device = _device_for_token(payload.device_id, authorization)
    token = generate_token()
    stored_token = hash_agent_token(token)
    with connect() as db:
        grace_until = _db_time(db, datetime.now(timezone.utc) + timedelta(seconds=CREDENTIAL_GRACE_SECONDS))
        db.execute(
            """
            UPDATE agent_credentials SET expires_at=?
            WHERE device_id=? AND active=? AND (expires_at IS NULL OR expires_at > ?)
            """,
            (grace_until, payload.device_id, True, grace_until),
        )
        db.execute(
            "INSERT INTO agent_credentials(device_id, token) VALUES (?, ?)",
            (payload.device_id, stored_token),
        )
        db.execute("UPDATE devices SET token=? WHERE device_id=?", (stored_token, payload.device_id))
        audit(db, f"agent:{payload.device_id}", "device.credential_rotated", target_type="device",
              target_id=payload.device_id, details={"previous_credential_id": device["credential_id"]})
    return {"device_id": payload.device_id, "token": token, "grace_seconds": CREDENTIAL_GRACE_SECONDS}


@app.post("/api/agent/results")
def receive_results(
    payload: ScanRequest, request: Request, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    device = _device_for_token(payload.device_id, authorization)
    new_findings: list[dict[str, Any]] = []
    if payload.scan_type not in ALLOWED_TASKS:
        raise HTTPException(status_code=400, detail="Tipo de tarea no permitido")

    with connect() as db:
        if payload.request_id:
            duplicate = db.execute(
                "SELECT id FROM scans WHERE device_id=? AND request_id=?",
                (payload.device_id, payload.request_id),
            ).fetchone()
            if duplicate:
                return {"scan_id": duplicate["id"], "evaluated_rules": 0, "duplicate": True}
        if payload.task_id is not None:
            task = db.execute("SELECT * FROM tasks WHERE id=?", (payload.task_id,)).fetchone()
            if (
                not task
                or task["device_id"] != payload.device_id
                or task["task_type"] != payload.scan_type
                or task["status"] not in {"delivered", "completed"}
            ):
                raise HTTPException(status_code=409, detail="La tarea no esta entregada a este equipo")

        rule_results = evaluate_rules(payload.evidence, kev=kev_catalog.catalog(), msrc=msrc_catalog.catalog())
        db.execute(
            "UPDATE devices SET last_seen = CURRENT_TIMESTAMP, offline_alerted=? WHERE device_id = ?",
            (False, payload.device_id),
        )
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
            INSERT INTO scans(device_id, scan_type, status, completed_at, duration_ms, modules_success, modules_error,
                request_id, task_id)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
            """,
            (
                payload.device_id,
                payload.scan_type,
                "partial" if _int_or_none((payload.evidence.get("scan_metadata") or {}).get("modules_error")) else "completed",
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("duration_ms")),
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("modules_success")),
                _int_or_none((payload.evidence.get("scan_metadata") or {}).get("modules_error")),
                payload.request_id,
                payload.task_id,
            ),
        )
        for control, value in status_evidence(payload.evidence).items():
            db.execute(
                "INSERT INTO evidences(scan_id, device_id, control, result_json) VALUES (?, ?, ?, ?)",
                (scan_id, payload.device_id, f"status_{control}", json_dumps(value)),
            )
        maybe_store_snapshot(db, payload.device_id, scan_id, payload.evidence)
        prune_device_history(db, payload.device_id)
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
                    if previous == "resolved":
                        new_findings.append(_alert_item(result))
                    # The diagnosis is refreshed on every scan so it always
                    # names what is wrong right now (accounts, KBs, IPs...).
                    db.execute(
                        """
                        UPDATE findings SET status=?, severity=?, title=?, recommendation=?, closure_criteria=?,
                            details_json=?, last_scan_id=?, resolved_scan_id=NULL, updated_at=CURRENT_TIMESTAMP
                        WHERE id=?
                        """,
                        (
                            new_status, result.severity, result.title, result.recommendation,
                            result.closure_criteria, json_dumps(result.diagnosis()), scan_id, existing["id"],
                        ),
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
                            closure_criteria, details_json, first_scan_id, last_scan_id)
                        VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
                        """,
                        (
                            payload.device_id,
                            result.rule_id,
                            result.control,
                            result.title,
                            result.severity,
                            result.recommendation,
                            result.closure_criteria,
                            json_dumps(result.diagnosis()),
                            scan_id,
                            scan_id,
                        ),
                    )
                    db.execute(
                        "INSERT INTO history(finding_id, previous_status, new_status, note, scan_id) VALUES (?, NULL, 'open', ?, ?)",
                        (finding_id, (result.detail or "Hallazgo generado por el motor de reglas.")[:1000], scan_id),
                    )
                    new_findings.append(_alert_item(result))
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
        if payload.task_id is not None:
            db.execute(
                """
                UPDATE tasks SET status='completed', completed_at=CURRENT_TIMESTAMP,
                    result_scan_id=?, last_error=NULL
                WHERE id=? AND device_id=?
                """,
                (scan_id, payload.task_id, payload.device_id),
            )
        if new_findings and alerts.smtp_configured():
            alerts.notify_async(
                _alert_recipients(db, device["company_id"]),
                system_info.get("hostname") or device.get("name") or payload.device_id,
                new_findings,
                f"{_public_base_url(request)}/devices/{payload.device_id}",
            )
        return {"scan_id": scan_id, "evaluated_rules": len(rule_results), "duplicate": False}


EVENTS_KEPT_PER_DEVICE = 3000
EVENT_EMAIL_INTERVAL_SECONDS = 600
_event_email_last: dict[str, float] = {}


@app.post("/api/agent/events")
def receive_events(
    payload: EventBatch, request: Request, authorization: str | None = Header(default=None)
) -> dict[str, Any]:
    """Near-real-time security events pushed by the agent's monitor."""
    device = _device_for_token(payload.device_id, authorization)
    accepted: list[AgentEvent] = []
    with connect() as db:
        for item in payload.events:
            data_json = json_dumps(item.data)
            if len(data_json) > 4000:
                data_json = json_dumps({"truncated": True})
            inserted = db.execute(
                """
                INSERT INTO device_events(device_id, event_key, event_type, severity, title, detail, data_json, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, event_key) DO NOTHING
                """,
                (payload.device_id, item.event_key, item.event_type, item.severity, item.title,
                 item.detail, data_json, item.occurred_at),
            )
            if inserted.rowcount == 1:
                accepted.append(item)
        db.execute(
            "UPDATE devices SET last_seen=CURRENT_TIMESTAMP, offline_alerted=? WHERE device_id=?",
            (False, payload.device_id),
        )
        # Bound storage per device (offset query works on SQLite and PostgreSQL).
        cutoff = db.execute(
            "SELECT id FROM device_events WHERE device_id=? ORDER BY id DESC LIMIT 1 OFFSET ?",
            (payload.device_id, EVENTS_KEPT_PER_DEVICE),
        ).fetchone()
        if cutoff:
            db.execute("DELETE FROM device_events WHERE device_id=? AND id<=?", (payload.device_id, cutoff["id"]))
        serious = [
            {"severity": item.severity, "title": item.title, "detail": item.detail}
            for item in accepted if item.severity in {"Critico", "Alto"}
        ]
        now = time.time()
        if serious and alerts.smtp_configured() and now - _event_email_last.get(payload.device_id, 0) >= EVENT_EMAIL_INTERVAL_SECONDS:
            _event_email_last[payload.device_id] = now
            alerts.notify_async(
                _alert_recipients(db, device["company_id"]),
                device.get("name") or payload.device_id,
                serious,
                f"{_public_base_url(request)}/devices/{payload.device_id}",
            )
    return {"accepted": len(accepted), "duplicates": len(payload.events) - len(accepted)}


def _event_view(row: Any) -> dict[str, Any]:
    event = dict(row)
    event["data"] = json_loads(event.pop("data_json", None)) or {}
    event.pop("event_key", None)
    return event


@app.get("/api/events")
def list_events(
    request: Request,
    after_id: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=300),
    device_id: str | None = None,
) -> dict[str, Any]:
    """Live feed for the caller's company, newest first; poll with ``after_id``."""
    _require_user(request)
    company_id = _company_id(request)
    device_filter = "AND e.device_id = ?" if device_id else ""
    params = (company_id, after_id, *((device_id,) if device_id else ()), limit)
    with connect() as db:
        if device_id:
            _company_device(db, device_id, company_id)
        rows = db.execute(
            f"""
            SELECT e.id, e.device_id, d.name AS device_name, e.event_type, e.severity, e.title, e.detail,
                e.data_json, e.occurred_at, e.created_at
            FROM device_events e JOIN devices d ON d.device_id = e.device_id
            WHERE d.company_id = ? AND e.id > ? {device_filter}
            ORDER BY e.id DESC LIMIT ?
            """,
            params,
        ).fetchall()
    events = [_event_view(row) for row in rows]
    return {"events": events, "latest_id": max((item["id"] for item in events), default=after_id)}


@app.get("/api/agent/tasks")
def agent_tasks(
    device_id: str,
    max_tasks: int = Query(default=10, ge=1, le=10),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _device_for_token(device_id, authorization)
    with connect() as db:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=TASK_LEASE_SECONDS)
        cutoff_value: Any = cutoff if db.is_postgres else cutoff.strftime("%Y-%m-%d %H:%M:%S")
        candidates = db.execute(
            """
            SELECT * FROM tasks
            WHERE device_id = ? AND (
                status='pending' OR (status='delivered' AND (delivered_at IS NULL OR delivered_at < ?))
            )
            ORDER BY created_at
            LIMIT ?
            """,
            (device_id, cutoff_value, max_tasks),
        ).fetchall()
        claimed_ids: list[int] = []
        for row in candidates:
            claimed = db.execute(
                """
                UPDATE tasks SET status='delivered', delivered_at=CURRENT_TIMESTAMP,
                    delivery_attempts=delivery_attempts+1
                WHERE id=? AND device_id=? AND (
                    status='pending' OR (status='delivered' AND (delivered_at IS NULL OR delivered_at < ?))
                )
                """,
                (row["id"], device_id, cutoff_value),
            )
            if claimed.rowcount == 1:
                claimed_ids.append(row["id"])
        if not claimed_ids:
            return {"tasks": []}
        placeholders = ",".join("?" for _ in claimed_ids)
        rows = db.execute(
            f"SELECT * FROM tasks WHERE id IN ({placeholders}) ORDER BY created_at", claimed_ids
        ).fetchall()
        return {"tasks": [dict(row) for row in rows]}


@app.post("/api/tasks")
def create_task(payload: TaskRequest, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "technician")
    company_id = _company_id(request)
    if payload.task_type not in ALLOWED_TASKS:
        raise HTTPException(status_code=400, detail="Tipo de tarea no permitido")
    with connect() as db:
        _company_device(db, payload.device_id, company_id)
        existing = db.execute(
            """
            SELECT id, status FROM tasks
            WHERE device_id=? AND task_type=? AND status IN ('pending', 'delivered')
            ORDER BY created_at DESC LIMIT 1
            """,
            (payload.device_id, payload.task_type),
        ).fetchone()
        if existing:
            return {"task_id": existing["id"], "status": existing["status"], "deduplicated": True}
        task_id = insert_returning_id(
            db,
            "INSERT INTO tasks(device_id, task_type, parameters_json) VALUES (?, ?, ?)",
            (payload.device_id, payload.task_type, json_dumps(payload.parameters)),
        )
        audit(db, actor, "task.create", target_type="device", target_id=payload.device_id,
              details={"task_id": task_id, "task_type": payload.task_type},
              source=_client_hash(request), company_id=company_id)
        return {"task_id": task_id, "status": "pending", "deduplicated": False}


@app.post("/api/devices/{device_id}/reconnect")
def reconnect_device(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request, "technician")
    with connect() as db:
        view = device_view(_company_device(db, device_id, _company_id(request)))
    if view["agent_status"] == "online":
        return {
            "device_id": device_id, "agent_status": "online", "agent_status_label": view["agent_status_label"],
            "message": "El agente esta conectado y reportando con normalidad.", "steps": [], "commands": [],
        }
    return {
        "device_id": device_id,
        "agent_status": view["agent_status"],
        "agent_status_label": view["agent_status_label"],
        "message": (
            f"Ultimo contacto: {view.get('last_seen') or 'nunca'}. El agente se reconecta solo cuando el equipo "
            "esta encendido y con Internet; Windows reinicia el servicio si se detiene. Si no vuelve:"
        ),
        "steps": [
            "Verifica que la computadora este encendida y conectada a Internet.",
            "Si el equipo se reinstalo o se le borro el agente, pulsa 'Agregar computadora' y ejecuta el instalador "
            "en ese equipo: conserva o renueva su registro automaticamente.",
            "Si el equipo ya no existe, eliminalo del panel con el boton 'Eliminar'.",
        ],
        "commands": [],
    }


@app.post("/api/devices/{device_id}/rotate-credential")
def request_credential_rotation(device_id: str, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        _company_device(db, device_id, company_id)
        db.execute(
            "UPDATE devices SET credential_rotation_requested=? WHERE device_id=?",
            (True, device_id),
        )
        audit(db, actor, "device.rotation_requested", target_type="device", target_id=device_id,
              source=_client_hash(request), company_id=company_id)
    return {
        "device_id": device_id,
        "status": "rotation_requested",
        "message": "El agente renovara su credencial en su proximo heartbeat; la anterior se retira al usar la nueva.",
    }


@app.post("/api/devices/{device_id}/disconnect")
def disconnect_device(device_id: str, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        _company_device(db, device_id, company_id)
        db.execute("UPDATE agent_credentials SET active=? WHERE device_id=?", (False, device_id))
        db.execute(
            "UPDATE tasks SET status='canceled', completed_at=CURRENT_TIMESTAMP WHERE device_id=? AND status IN ('pending', 'delivered')",
            (device_id,),
        )
        audit(db, actor, "device.disconnect", target_type="device", target_id=device_id,
              source=_client_hash(request), company_id=company_id)
    return {
        "device_id": device_id,
        "status": "disconnected",
        "message": "Agente desconectado. Sus credenciales quedaron desactivadas y las tareas pendientes fueron canceladas.",
    }


@app.post("/api/devices/{device_id}/reactivate")
def reactivate_device(device_id: str, request: Request) -> dict[str, Any]:
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        _company_device(db, device_id, company_id)
        # Only the newest credential comes back; tokens superseded by a
        # rotation must stay retired.
        db.execute(
            """
            UPDATE agent_credentials SET active=?, expires_at=NULL
            WHERE id = (SELECT MAX(id) FROM agent_credentials WHERE device_id=?)
            """,
            (True, device_id),
        )
        audit(db, actor, "device.reactivate", target_type="device", target_id=device_id,
              source=_client_hash(request), company_id=company_id)
    return {
        "device_id": device_id,
        "status": "active",
        "message": "Agente reactivado. El token existente puede volver a enviar heartbeat y evidencia.",
    }


# Child rows first: SQLite enforces these foreign keys.
DEVICE_TABLES = (
    "evidences", "snapshot_diffs", "inventory_snapshots", "tasks", "scans", "device_events",
    "security_alerts", "device_group_members", "policy_assignments", "agent_credentials",
)


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: str, request: Request) -> dict[str, Any]:
    """Remove a device and all of its history (findings, scans, evidence, events)."""
    actor = _require_user(request, "admin")
    company_id = _company_id(request)
    with connect() as db:
        device = _company_device(db, device_id, company_id)
        db.execute(
            "DELETE FROM history WHERE finding_id IN (SELECT id FROM findings WHERE device_id=?)", (device_id,)
        )
        db.execute("DELETE FROM findings WHERE device_id=?", (device_id,))
        for table in DEVICE_TABLES:
            db.execute(f"DELETE FROM {table} WHERE device_id=?", (device_id,))
        db.execute("DELETE FROM devices WHERE device_id=?", (device_id,))
        audit(db, actor, "device.delete", target_type="device", target_id=device_id,
              details={"hostname": device.get("hostname") or device.get("name")},
              source=_client_hash(request), company_id=company_id)
    _event_email_last.pop(device_id, None)
    return {
        "device_id": device_id,
        "status": "deleted",
        "message": "Computadora eliminada con todo su historial. Si el agente sigue instalado en ese equipo, "
                   "desinstalalo desde Configuracion > Aplicaciones; ya no puede enviar datos.",
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
            WHERE d.device_id = ? AND d.company_id = ?
            """,
            (True, device_id, _company_id(request)),
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
        findings = [finding_view(dict(row)) for row in db.execute(
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
    software_result = (latest_controls.get("software_inventory") or {}).get("data")
    vulnerabilities = vulndb.device_vulnerabilities(
        (latest_controls.get("updates") or {}).get("data"),
        software_result.get("data") if isinstance(software_result, dict) and software_result.get("success") is True else None,
        kev_catalog.catalog(),
        msrc_catalog.catalog(),
    )
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
            **{f"security_{key}": value for key, value in security_score(findings).items() if key != "open_findings"},
        },
        "collection_issues": collection_issues(latest_controls),
        "vulnerabilities": vulnerabilities,
        "kev_loaded": kev_catalog.catalog() is not None,
        "msrc_loaded": msrc_catalog.catalog() is not None,
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
        if task["status"] == "completed":
            return {"status": "completed"}
        if task["status"] != "delivered":
            raise HTTPException(status_code=409, detail="La tarea no fue entregada")
        db.execute("UPDATE tasks SET status='completed', completed_at=CURRENT_TIMESTAMP WHERE id=?", (task_id,))
        return {"status": "completed"}


@app.post("/api/agent/tasks/{task_id}/fail")
def fail_task(
    task_id: int,
    payload: TaskFailureRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(status_code=404, detail="Tarea no existe")
        _device_for_token(task["device_id"], authorization)
        if task["status"] == "failed":
            return {"status": "failed"}
        if task["status"] != "delivered":
            raise HTTPException(status_code=409, detail="La tarea no fue entregada")
        db.execute(
            "UPDATE tasks SET status='failed', completed_at=CURRENT_TIMESTAMP, last_error=? WHERE id=?",
            (payload.error, task_id),
        )
        return {"status": "failed"}


@app.get("/health/live")
def health_live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def health_ready() -> Response:
    try:
        with connect() as db:
            db.execute("SELECT 1").fetchone()
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return JSONResponse({"status": "ready"})


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    _require_user(request)
    company_id = _company_id(request)
    scope = (company_id,)
    in_company = "device_id IN (SELECT device_id FROM devices WHERE company_id=?)"
    with connect() as db:
        evidences = [dict(row) for row in db.execute(
            f"""
            SELECT * FROM (
                SELECT e.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY e.device_id, e.control
                        ORDER BY e.created_at DESC, e.id DESC
                    ) AS evidence_rank
                FROM evidences e
                WHERE e.{in_company}
            ) latest
            WHERE evidence_rank=1
            ORDER BY created_at DESC, id DESC
            LIMIT 2000
            """,
            scope,
        )]
        for evidence in evidences:
            evidence.pop("evidence_rank", None)
        devices = [device_view(dict(row)) for row in db.execute(
            """
            SELECT d.*,
                EXISTS(SELECT 1 FROM agent_credentials c WHERE c.device_id=d.device_id AND c.active=?) AS credential_active
            FROM devices d
            WHERE d.company_id=?
            ORDER BY last_seen DESC NULLS LAST
            """,
            (True, company_id),
        )]
        findings = [finding_view(dict(row)) for row in db.execute(
            f"SELECT * FROM findings WHERE {in_company} ORDER BY updated_at DESC", scope
        )]
        open_findings = [finding for finding in findings if finding["status"] != "resolved"]
        for device in devices:
            device.update({
                f"security_{key}": value
                for key, value in security_score(
                    [finding for finding in findings if finding["device_id"] == device["device_id"]]
                ).items()
            })
        scores = [device["security_score"] for device in devices]
        return {
            "devices": devices,
            "findings": findings,
            "evidences": evidences,
            "scans": [dict(row) for row in db.execute(
                f"SELECT * FROM scans WHERE {in_company} ORDER BY created_at DESC LIMIT 20", scope
            )],
            "tasks": [dict(row) for row in db.execute(
                f"SELECT * FROM tasks WHERE {in_company} ORDER BY created_at DESC LIMIT 20", scope
            )],
            "history": [dict(row) for row in db.execute(
                f"""
                SELECT * FROM history WHERE finding_id IN (SELECT id FROM findings WHERE {in_company})
                ORDER BY created_at DESC LIMIT 40
                """,
                scope,
            )],
            "summary": {
                "security_score": round(sum(scores) / len(scores)) if scores else None,
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
        return company_ai_summary(db, _company_id(request))


@app.post("/api/ai/company-chat")
def ai_company_chat(payload: AiChatRequest, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        return answer_company_question(db, _company_id(request), payload.question)


@app.get("/api/devices/{device_id}/ai-summary")
def ai_device_summary(device_id: str, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        _company_device(db, device_id, _company_id(request))
        return device_ai_summary(db, device_id)


@app.post("/api/devices/{device_id}/ai-chat")
def ai_device_chat(device_id: str, payload: AiChatRequest, request: Request) -> dict[str, Any]:
    _require_user(request)
    with connect() as db:
        _company_device(db, device_id, _company_id(request))
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
        antivirus_data = controls["antivirus"].get("data") or {}
        threats_error = (antivirus_data.get("collection_errors") or {}).get("threats")
        controls["threats"] = {
            "control": "threats",
            "label": CONTROL_TABS["threats"],
            "scan_id": controls["antivirus"].get("scan_id"),
            "scan_type": controls["antivirus"].get("scan_type"),
            "created_at": controls["antivirus"].get("created_at"),
            "data": {
                "active_threat_count": antivirus_data.get("active_threat_count"),
                "threats": antivirus_data.get("threats", []),
                "status": "error" if threats_error else antivirus_data.get("status"),
                "error": threats_error or antivirus_data.get("error"),
            },
        }
    return controls


def _alert_recipients(db: Any, company_id: int) -> list[str]:
    return [
        row["username"] for row in db.execute(
            """
            SELECT username FROM users
            WHERE company_id=? AND active=? AND role IN ('admin', 'technician') AND username LIKE '%@%'
            """,
            (company_id, True),
        ).fetchall()
    ]


def check_offline_devices() -> int:
    """Alert once per outage about enrolled devices that stopped reporting."""
    if not alerts.smtp_configured():
        return 0
    notified = 0
    panel = os.getenv("PUBLIC_BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "el panel de CyberCheck"
    with connect() as db:
        cutoff = _db_time(db, datetime.now(timezone.utc) - timedelta(hours=OFFLINE_ALERT_HOURS))
        rows = db.execute(
            """
            SELECT d.device_id, d.name, d.company_id, d.last_seen FROM devices d
            WHERE d.offline_alerted=? AND d.last_seen IS NOT NULL AND d.last_seen < ?
                AND EXISTS (SELECT 1 FROM agent_credentials c WHERE c.device_id=d.device_id AND c.active=?)
            """,
            (False, cutoff, True),
        ).fetchall()
        by_company: dict[int, list[Any]] = {}
        for row in rows:
            by_company.setdefault(int(row["company_id"]), []).append(row)
        for company_id, devices in by_company.items():
            recipients = _alert_recipients(db, company_id)
            if not recipients:
                continue
            ids = [item["device_id"] for item in devices]
            db.execute(
                f"UPDATE devices SET offline_alerted=? WHERE device_id IN ({','.join('?' for _ in ids)})",
                (True, *ids),
            )
            alerts.notify_offline_async(
                recipients,
                [{"name": item["name"], "last_seen": str(item["last_seen"])[:19]} for item in devices],
                OFFLINE_ALERT_HOURS,
                panel,
            )
            notified += len(devices)
    return notified


_watcher_started = False


def _offline_watcher() -> None:
    while True:
        time.sleep(OFFLINE_CHECK_SECONDS)
        try:
            check_offline_devices()
        except Exception:  # noqa: BLE001 - the watcher must never die
            logging.getLogger("cybercheck.alerts").exception("Fallo la revision de equipos sin reportar")


def start_offline_watcher() -> None:
    global _watcher_started
    if _watcher_started or not alerts.smtp_configured():
        return
    _watcher_started = True
    threading.Thread(target=_offline_watcher, name="cybercheck-offline-watcher", daemon=True).start()


def _alert_item(result: Any) -> dict[str, Any]:
    explanation = plain_language.explain(result.rule_id, result.severity, result.evidence) or {}
    return {
        "severity": result.severity,
        "title": explanation.get("title") or result.title,
        "detail": (f"{explanation['what']} ({explanation['who_label']}.)" if explanation else result.detail),
    }


SCANS_WITH_EVIDENCE = 40
SNAPSHOTS_WITH_DATA = 10


def prune_device_history(db: Any, device_id: str) -> None:
    """Bound storage: old scans keep their row, findings and diffs, but drop
    the bulky evidence payloads and full inventory snapshots."""
    old_scans = [
        row["id"] for row in db.execute(
            "SELECT id FROM scans WHERE device_id=? ORDER BY id DESC LIMIT 100000 OFFSET ?",
            (device_id, SCANS_WITH_EVIDENCE),
        ).fetchall()
    ]
    for start in range(0, len(old_scans), 500):
        chunk = old_scans[start:start + 500]
        # The newest row of every control survives even if its scan is old, so
        # the panel never loses the last known state of a control.
        db.execute(
            f"DELETE FROM evidences WHERE device_id=? AND scan_id IN ({','.join('?' for _ in chunk)}) "
            "AND id NOT IN (SELECT MAX(id) FROM evidences WHERE device_id=? GROUP BY control)",
            (device_id, *chunk, device_id),
        )
    old_snapshots = [
        row["id"] for row in db.execute(
            "SELECT id FROM inventory_snapshots WHERE device_id=? ORDER BY id DESC LIMIT 100000 OFFSET ?",
            (device_id, SNAPSHOTS_WITH_DATA),
        ).fetchall()
    ]
    for start in range(0, len(old_snapshots), 500):
        chunk = old_snapshots[start:start + 500]
        db.execute(
            f"UPDATE inventory_snapshots SET snapshot_json='{{}}' "
            f"WHERE id IN ({','.join('?' for _ in chunk)}) AND snapshot_json<>'{{}}'",
            tuple(chunk),
        )


@app.get("/favicon.ico")
def favicon() -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" '
        'fill="#176b87"/><text x="16" y="22" font-family="Arial" font-size="15" font-weight="700" '
        'text-anchor="middle" fill="#fff">CC</text></svg>'
    )
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})


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
        "hardening",
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
        if key == "administrators" and entry and "admin_policy" not in controls:
            status = "NOT_CONFIGURED"
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
    if isinstance(data, dict):
        if data.get("success") is False or data.get("error") or data.get("status") in {"error", "unavailable", "not_supported"}:
            return "NOT_AVAILABLE"
        if data.get("status") == "not_configured":
            return "NOT_CONFIGURED"
        if not data or ("success" in data and not data.get("data")):
            return "NOT_AVAILABLE"
        if control == "firewall" and any(not isinstance(data.get(profile), bool) for profile in ("domain", "private", "public")):
            return "NOT_AVAILABLE"
        if control == "updates" and (not isinstance(data.get("pending_count"), int) or not isinstance(data.get("reboot_pending"), bool)):
            return "NOT_AVAILABLE"
        if control == "antivirus" and any(not isinstance(data.get(key), bool) for key in ("enabled", "real_time")):
            return "NOT_AVAILABLE"
        if control == "threats" and data.get("active_threat_count") is None:
            return "NOT_AVAILABLE"
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


def security_score(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """0-100 score and A-F grade from a device's open findings."""
    open_findings = [item for item in findings if item.get("status") != "resolved"]
    penalty = sum(SEVERITY_WEIGHTS.get(str(item.get("severity", "")).lower(), 4) for item in open_findings)
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "open_findings": len(open_findings)}


def finding_view(row: dict[str, Any]) -> dict[str, Any]:
    finding = dict(row)
    finding["diagnosis"] = json_loads(finding.pop("details_json", None)) or {}
    # Findings stored before plain-language explanations existed get the
    # general version until the next scan refreshes them with exact details.
    if "quick_fix" not in finding["diagnosis"]:
        finding["diagnosis"]["quick_fix"] = fixes.fix_for(finding.get("rule_id", ""), {})
    if not finding["diagnosis"].get("plain"):
        finding["diagnosis"]["plain"] = plain_language.explain(
            finding.get("rule_id", ""), finding.get("severity", ""), {},
            has_fix=finding["diagnosis"]["quick_fix"] is not None,
        )
    return finding


def collection_issues(controls: dict[str, Any]) -> list[dict[str, Any]]:
    """Modules of the latest scan that could not verify their control, and why."""
    metadata = (controls.get("scan_metadata") or {}).get("data") or {}
    issues = []
    for module in metadata.get("modules") or []:
        if not isinstance(module, dict) or module.get("status") == "ok":
            continue
        error = str(module.get("error") or "sin detalle")
        lowered = error.lower()
        if "denied" in lowered or "denegado" in lowered or "administrator" in lowered or "system" in lowered:
            hint = "El agente no tuvo permisos suficientes: instalalo como servicio (se ejecuta como SYSTEM)."
        elif "timeout" in lowered or "timed out" in lowered:
            hint = "La consulta tardo demasiado; el equipo puede estar sobrecargado o Windows Update ocupado."
        elif "tercero" in lowered or "third" in lowered:
            hint = "Hay un antivirus de terceros; su estado debe verificarse en la consola de ese producto."
        else:
            hint = "Revisa el registro del agente en C:\\ProgramData\\CyberCheck\\logs\\agent.log."
        issues.append({
            "module": module.get("module"),
            "label": MODULE_LABELS.get(str(module.get("module")), module.get("module")),
            "status": module.get("status"),
            "error": error[:300],
            "hint": hint,
        })
    return issues


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
        "hardening",
        "security_detections",
    ):
        if key in evidence:
            controls[key] = evidence[key]
    if "listening_ports" in evidence:
        controls["ports"] = evidence["listening_ports"]
    if "services" in evidence:
        controls["services"] = evidence["services"]
    if "local_administrators" in evidence:
        controls["administrators"] = evidence["local_administrators"]
    if "authorized_local_admins" in evidence:
        controls["admin_policy"] = {"authorized_local_admins": evidence["authorized_local_admins"]}
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
