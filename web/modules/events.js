import { escapeHtml } from "./utils.js";

const URGENCY = { Critico: "Urgente", Alto: "Importante", Medio: "Aviso", Bajo: "Aviso", Info: "Información" };

export function timeAgo(value) {
  const stamp = new Date(value).getTime();
  if (Number.isNaN(stamp)) return "";
  const seconds = Math.max(0, Math.round((Date.now() - stamp) / 1000));
  if (seconds < 60) return `hace ${seconds} s`;
  if (seconds < 3600) return `hace ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `hace ${Math.floor(seconds / 3600)} h`;
  return new Date(stamp).toLocaleString();
}

// Everyday wording for each kind of event; the agent's technical detail is
// kept underneath for whoever gives IT support.
const FRIENDLY = {
  logon_failure_burst: (d) => [
    `Alguien intenta adivinar la contraseña de «${d.user || "una cuenta"}»`,
    `${d.count || "Varios"} intentos fallidos en pocos minutos${d.source_ip ? ` desde la dirección ${d.source_ip}` : " en esta computadora"}. Si no fuiste tú, cambia esa contraseña.`,
  ],
  account_created: (d) => [`Se creó una cuenta nueva: «${d.target_user || "?"}»`, "Si nadie la reconoce, avisa a tu técnico."],
  admin_group_change: () => ["Alguien recibió permisos de administrador", "Con esos permisos se puede hacer cualquier cosa en la computadora. Confirma que fue autorizado."],
  account_locked: (d) => [`Se bloqueó la cuenta «${d.target_user || "?"}»`, "Hubo demasiados intentos con contraseña equivocada."],
  log_cleared: () => ["Alguien borró el historial de seguridad", "Casi nunca es normal: suele hacerlo un intruso para borrar sus huellas. Avisa a tu técnico."],
  service_installed: (d) => [`Se instaló un programa que funciona en segundo plano: ${d.service_name || "?"}`, "Si no instalaste nada, avisa a tu técnico."],
  defender_event: (d) => [{
    1116: "El antivirus encontró un virus",
    1117: "El antivirus bloqueó o eliminó un virus",
    1118: "El antivirus no pudo eliminar un virus",
    1119: "El antivirus no pudo eliminar un virus",
    5001: "Alguien apagó el antivirus",
  }[d.event_id] || "Aviso del antivirus", ""],
  process_unsigned_user_path: (d) => [`Se abrió un programa sospechoso: ${d.name || "?"}`, "No tiene la firma de su fabricante y está en una carpeta personal. Si no lo reconoces, avisa a tu técnico."],
  new_listening_port: (d) => [`Un programa abrió una entrada desde la red (${d.port})`, `${d.process || "Un programa"} ahora acepta conexiones desde otras computadoras.`],
  usb_connected: (d) => [
    d.already_connected ? "Hay una memoria USB conectada" : "Se conectó una memoria USB",
    d.model ? `${d.model}. Si no es de la empresa, no abras sus archivos.` : "",
  ],
  usb_disconnected: (d) => ["Se desconectó una memoria USB", d.model || ""],
};

export function friendlyEvent(event) {
  const make = FRIENDLY[event.event_type];
  if (!make) return { title: event.title, summary: "" };
  const [title, summary] = make(event.data || {});
  return { title, summary };
}

export function eventRows(events, showDevice = true) {
  if (!events.length) {
    return `<p class="empty-state">Todavía no ha pasado nada. ¡Es buena señal!</p>`;
  }
  return events.map((event) => {
    const { title, summary } = friendlyEvent(event);
    return `
    <div class="live-event sev-${escapeHtml(event.severity)}">
      <span class="badge ${escapeHtml(event.severity)}">${escapeHtml(URGENCY[event.severity] || event.severity)}</span>
      <div class="live-body">
        <strong>${escapeHtml(title)}</strong>${showDevice ? ` <span class="muted">· ${escapeHtml(event.device_name || "")}</span>` : ""}
        ${summary ? `<div>${escapeHtml(summary)}</div>` : ""}
        ${event.detail ? `<div class="muted small-print">${escapeHtml(event.detail)}</div>` : ""}
      </div>
      <time class="muted" title="${escapeHtml(event.occurred_at)}">${escapeHtml(timeAgo(event.occurred_at))}</time>
    </div>
  `;
  }).join("");
}

// Live line per computer: is it reporting right now?
export function deviceHeartbeats(devices) {
  if (!devices.length) return "";
  return `<div class="heartbeats">${devices.map((device) => {
    const online = device.agent_status === "online";
    const seen = device.last_seen ? timeAgo(String(device.last_seen).replace(" ", "T") + (/[zZ]|[+-]\d\d:?\d\d$/.test(device.last_seen) ? "" : "Z")) : "nunca";
    return `
      <div class="heartbeat ${online ? "on" : "off"}">
        <span class="${online ? "live-dot" : "off-dot"}"></span>
        <strong>${escapeHtml(device.name || device.hostname || device.device_id)}</strong>
        <span class="muted">${online ? `Conectada y vigilando · última señal ${escapeHtml(seen)}` : `Sin conexión · última señal ${escapeHtml(seen)}`}</span>
      </div>`;
  }).join("")}</div>`;
}

export function isSerious(event) {
  return event.severity === "Critico" || event.severity === "Alto";
}
