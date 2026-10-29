from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import Any

from .storage import json_dumps

ROLE_LEVELS = {"viewer": 1, "technician": 2, "admin": 3}
ROLE_LABELS = {"viewer": "Solo lectura", "technician": "Tecnico", "admin": "Administrador"}
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
MIN_PASSWORD_LENGTH = 12

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str | None) -> bool:
    try:
        scheme, n, r, p, salt, expected = (stored or "").split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(_unb64(expected)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, _unb64(expected))


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def burn_password_check(password: str) -> None:
    """Spend the same time as a real check so unknown usernames are not revealed."""
    verify_password(password, _DUMMY_HASH)


def validate_username(username: str) -> str:
    username = username.strip()
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("El usuario debe tener 3-64 caracteres: letras, numeros, punto, guion o guion bajo")
    return username


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"La contrasena debe tener al menos {MIN_PASSWORD_LENGTH} caracteres")
    if password.lower() in {"admin123", "password1234", "changeme1234"}:
        raise ValueError("La contrasena es demasiado comun")


def validate_role(role: str) -> str:
    if role not in ROLE_LEVELS:
        raise ValueError("Rol no permitido")
    return role


def role_allows(role: str | None, minimum: str) -> bool:
    return ROLE_LEVELS.get(role or "", 0) >= ROLE_LEVELS[minimum]


def audit(
    db: Any,
    actor: str,
    action: str,
    *,
    target_type: str | None = None,
    target_id: Any = None,
    details: dict[str, Any] | None = None,
    source: str | None = None,
) -> None:
    db.execute(
        """
        INSERT INTO admin_audit_log(actor, action, target_type, target_id, details_json, source_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            actor[:120],
            action[:80],
            target_type,
            None if target_id is None else str(target_id)[:120],
            json_dumps(details or {}),
            source,
        ),
    )


def public_user(row: Any) -> dict[str, Any]:
    user = dict(row)
    user.pop("password_hash", None)
    user.pop("session_epoch", None)
    user["active"] = user.get("active") not in {False, 0, "0"}
    user["role_label"] = ROLE_LABELS.get(user.get("role"), user.get("role"))
    return user
