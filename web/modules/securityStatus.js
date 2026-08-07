import { escapeHtml, parseJson } from "./utils.js";
import { yesNo } from "./labels.js";

export function latestStatusEvidence(evidences) {
  return evidences.reduce((index, item) => {
    if (!item.control || !item.control.startsWith("status_")) return index;
    const control = item.control.replace("status_", "");
    if (!index[control]) {
      index[control] = parseJson(item.result_json, { raw: item.result_json });
    }
    return index;
  }, {});
}

export function renderSecurityStatus(status) {
  const cards = [
    antivirusStatus(status.antivirus),
    firewallStatus(status.firewall),
    updateStatus(status.updates),
    deviceStatus(status.connected_devices),
    portStatus(status.ports),
    backupStatus(status.backup),
  ].filter(Boolean);
  if (!cards.length) {
    return `<p class="empty-state">Aun no hay evidencia de estado. Solicita una revision completa o una revision de antivirus y deja correr el agente.</p>`;
  }
  return cards.map((card) => `
    <article class="status-card ${card.level}">
      <div class="status-card-head">
        <strong>${escapeHtml(card.title)}</strong>
        <span class="badge ${card.level}">${escapeHtml(card.label)}</span>
      </div>
      <p>${escapeHtml(card.detail)}</p>
      ${card.items.length ? `<ul>${card.items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
    </article>
  `).join("");
}

function antivirusStatus(data) {
  if (!data) return null;
  const enabled = data.enabled === true && data.real_time === true;
  const threats = Number(data.active_threat_count || 0);
  const level = threats > 0 || !enabled ? "critical" : "ok";
  return {
    title: "Antivirus",
    label: level === "ok" ? "Protegido" : "Revisar",
    detail: `${data.name || "Antivirus"}: activo=${yesNo(data.enabled)}, tiempo real=${yesNo(data.real_time)}, amenazas activas=${threats}.`,
    level,
    items: [
      `Firmas: ${data.signature_age_days ?? "sin dato"} dias`,
      `Ultimo escaneo rapido: ${data.quick_scan_age_days ?? "sin dato"} dias`,
      `Proteccion contra manipulacion: ${yesNo(data.tamper_protected)}`,
    ],
  };
}

function firewallStatus(data) {
  if (!data) return null;
  const ok = data.domain !== false && data.private !== false && data.public !== false;
  return {
    title: "Firewall",
    label: ok ? "Activo" : "Revisar",
    detail: `Dominio=${yesNo(data.domain)}, Privado=${yesNo(data.private)}, Publico=${yesNo(data.public)}.`,
    level: ok ? "ok" : "high",
    items: [],
  };
}

function updateStatus(data) {
  if (!data) return null;
  const pending = Number(data.pending_count || 0);
  return {
    title: "Windows Update",
    label: pending || data.reboot_pending ? "Pendiente" : "Al dia",
    detail: `${pending} actualizaciones pendientes. Reinicio pendiente=${yesNo(data.reboot_pending)}.`,
    level: pending || data.reboot_pending ? "medium" : "ok",
    items: [],
  };
}

function deviceStatus(data) {
  if (!data) return null;
  const usb = Number(data.usb_storage_count || 0);
  const unsigned = Number(data.unsigned_driver_count || 0);
  const errors = Number(data.device_error_count || 0);
  const level = unsigned ? "high" : (usb || errors ? "medium" : "ok");
  return {
    title: "Dispositivos conectados",
    label: level === "ok" ? "Normal" : "Revisar",
    detail: `${data.device_count || 0} dispositivos revisados, ${usb} USB de almacenamiento, ${unsigned} controladores sin firma, ${errors} con error.`,
    level,
    items: (data.usb_storage || []).slice(0, 3).map((item) => `USB: ${item.Model || item.FriendlyName || "Dispositivo"}`),
  };
}

function portStatus(data) {
  if (!Array.isArray(data)) return null;
  const risky = data.filter((item) => [3389, 5985, 5986, 445, 139].includes(Number(item.port)));
  return {
    title: "Puertos escuchando",
    label: risky.length ? "Expuestos" : "Sin riesgo comun",
    detail: `${data.length} puertos locales escuchando. Riesgo comun detectado: ${risky.length}.`,
    level: risky.length ? "high" : "ok",
    items: risky.slice(0, 5).map((item) => `${item.port} ${item.process_name || ""}`.trim()),
  };
}

function backupStatus(data) {
  if (!data) return null;
  const ok = data.exists === true && Number(data.days_since_last_backup || 999) <= 7;
  return {
    title: "Respaldo",
    label: ok ? "Reciente" : "Revisar",
    detail: data.exists ? `Ultimo respaldo hace ${data.days_since_last_backup ?? "sin dato"} dias.` : "No se encontro respaldo valido.",
    level: ok ? "ok" : "high",
    items: data.latest_file ? [`Archivo: ${data.latest_file}`, `Tamano: ${data.latest_size || 0} bytes`] : [],
  };
}
