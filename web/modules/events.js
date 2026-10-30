import { escapeHtml } from "./utils.js";

export function timeAgo(value) {
  const stamp = new Date(value).getTime();
  if (Number.isNaN(stamp)) return "";
  const seconds = Math.max(0, Math.round((Date.now() - stamp) / 1000));
  if (seconds < 60) return `hace ${seconds} s`;
  if (seconds < 3600) return `hace ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `hace ${Math.floor(seconds / 3600)} h`;
  return new Date(stamp).toLocaleString();
}

export function eventRows(events, showDevice = true) {
  if (!events.length) {
    return `<p class="empty-state">Sin eventos todavia. Aqui aparecen en segundos los intentos de acceso, cuentas nuevas, amenazas, procesos sin firma, puertos y USB.</p>`;
  }
  return events.map((event) => `
    <div class="live-event sev-${escapeHtml(event.severity)}">
      <span class="badge ${escapeHtml(event.severity)}">${escapeHtml(event.severity)}</span>
      <div class="live-body">
        <strong>${escapeHtml(event.title)}</strong>${showDevice ? ` <span class="muted">· ${escapeHtml(event.device_name || "")}</span>` : ""}
        ${event.detail ? `<div class="muted">${escapeHtml(event.detail)}</div>` : ""}
      </div>
      <time class="muted" title="${escapeHtml(event.occurred_at)}">${escapeHtml(timeAgo(event.occurred_at))}</time>
    </div>
  `).join("");
}

export function isSerious(event) {
  return event.severity === "Critico" || event.severity === "Alto";
}
