"""E-mail alerts for newly detected problems (optional, SMTP configured by env).

Set SMTP_HOST (and normally SMTP_USER / SMTP_PASSWORD / SMTP_FROM) to turn it
on. Delivery runs in a background thread so a slow mail server never delays
the agent's result upload.
"""
from __future__ import annotations

import logging
import os
import smtplib
import threading
from email.message import EmailMessage
from typing import Any

LOGGER = logging.getLogger("cybercheck.alerts")
ALERT_SEVERITIES = {"critico", "critical", "alto", "high"}


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST"))


def alertable(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in findings if str(item.get("severity", "")).lower() in ALERT_SEVERITIES]


def build_message(
    recipients: list[str], device_name: str, findings: list[dict[str, Any]], panel_url: str
) -> EmailMessage:
    ordered = sorted(findings, key=lambda item: 0 if str(item["severity"]).lower() in {"critico", "critical"} else 1)
    critical = sum(1 for item in ordered if str(item["severity"]).lower() in {"critico", "critical"})
    message = EmailMessage()
    message["Subject"] = (
        f"[CyberCheck] {critical} problema(s) CRITICO(S) en {device_name}" if critical
        else f"[CyberCheck] {len(ordered)} problema(s) nuevo(s) en {device_name}"
    )
    message["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER") or "cybercheck@localhost"
    message["To"] = ", ".join(recipients)
    lines = [f"Se detectaron problemas nuevos en la computadora {device_name}:", ""]
    for item in ordered:
        lines.append(f"- [{item['severity']}] {item['title']}")
        if item.get("detail"):
            lines.append(f"    {item['detail']}")
    lines += ["", f"Diagnostico completo y como corregirlo: {panel_url}", "",
              "Recibes este correo porque eres administrador o tecnico de esta cuenta de CyberCheck."]
    message.set_content("\n".join(lines))
    return message


def deliver(message: EmailMessage) -> bool:
    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    try:
        if port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if port != 465 and os.getenv("SMTP_STARTTLS", "true").lower() != "false":
                server.starttls()
            if user and password:
                server.login(user, password)
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        LOGGER.error("No se pudo enviar la alerta: %s: %s", type(exc).__name__, str(exc)[:200])
        return False


def send_async(message: EmailMessage) -> None:
    threading.Thread(target=deliver, args=(message,), name="cybercheck-alert", daemon=True).start()


def _plain_message(recipients: list[str], subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER") or "cybercheck@localhost"
    message["To"] = ", ".join(recipients)
    message.set_content(body)
    return message


def notify_offline_async(recipients: list[str], devices: list[dict[str, Any]], hours: int, panel_url: str) -> None:
    if not (smtp_configured() and recipients and devices):
        return
    lines = [f"Estas computadoras dejaron de reportar hace mas de {hours} horas:", ""]
    lines += [f"- {item['name']} (ultimo contacto: {item['last_seen']})" for item in devices]
    lines += [
        "", "Puede ser un equipo apagado o sin Internet, pero tambien alguien pudo desactivar el agente. "
        "Verificalo cuanto antes.", f"Panel: {panel_url}",
    ]
    send_async(_plain_message(recipients, f"[CyberCheck] {len(devices)} equipo(s) dejaron de reportar", "\n".join(lines)))


def send_password_reset(recipient: str, link: str) -> None:
    if not smtp_configured():
        return
    send_async(_plain_message(
        [recipient], "[CyberCheck] Restablecer tu contrasena",
        "Recibimos una solicitud para restablecer la contrasena de tu cuenta de CyberCheck.\n\n"
        f"Abre este enlace (valido por 1 hora, un solo uso):\n{link}\n\n"
        "Si no fuiste tu, ignora este mensaje: tu contrasena no cambia.",
    ))


def notify_async(recipients: list[str], device_name: str, findings: list[dict[str, Any]], panel_url: str) -> None:
    alerts = alertable(findings)
    if not (smtp_configured() and recipients and alerts):
        return
    send_async(build_message(recipients, device_name, alerts, panel_url))
