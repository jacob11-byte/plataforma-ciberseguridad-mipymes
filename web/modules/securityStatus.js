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

function unavailable(data) {
  return !data || data.success === false || Boolean(data.error)
    || ["error", "unavailable", "not_supported"].includes(data.status);
}

function unavailableCard(title, data, fallback = "La consulta no produjo evidencia suficiente.") {
  return {
    title,
    label: "No evaluado",
    detail: data?.error || fallback,
    level: "medium",
    items: [],
  };
}

function antivirusStatus(data) {
  if (!data) return null;
  if (unavailable(data) || data.enabled == null || data.real_time == null) {
    return unavailableCard("Antivirus", data);
  }
  const enabled = data.enabled === true && data.real_time === true;
  const threats = data.active_threat_count == null ? null : Number(data.active_threat_count);
  const level = threats > 0 || !enabled ? "critical" : "ok";
  return {
    title: "Antivirus",
    label: level === "ok" ? "Protegido" : "Revisar",
    detail: `${data.name || "Antivirus"}: activo=${yesNo(data.enabled)}, tiempo real=${yesNo(data.real_time)}, amenazas activas=${threats ?? "sin dato"}.`,
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
  if (unavailable(data) || ["domain", "private", "public"].some((key) => data[key] == null)) {
    return unavailableCard("Firewall", data);
  }
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
  if (unavailable(data) || data.pending_count == null || data.reboot_pending == null) {
    return unavailableCard("Windows Update", data);
  }
  const pending = Number(data.pending_count);
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
  if (unavailable(data) || ["usb_storage", "unsigned_drivers", "device_errors"].some((key) => !Array.isArray(data[key]))) {
    return unavailableCard("Dispositivos conectados", data);
  }
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
  if (data && !Array.isArray(data)) return unavailableCard("Puertos escuchando", data);
  if (!Array.isArray(data)) return null;
  const risky = data.filter((item) => [3389, 5985, 5986, 445, 139].includes(Number(item.port)));
  return {
    title: "Puertos escuchando",
    label: risky.length ? "Escucha de riesgo" : "Sin escucha de riesgo comun",
    detail: `${data.length} puertos en escucha local. Puertos de riesgo comun: ${risky.length}. La exposicion desde la red requiere otra comprobacion.`,
    level: risky.length ? "high" : "ok",
    items: risky.slice(0, 5).map((item) => `${item.port} ${item.process_name || ""}`.trim()),
  };
}

function backupStatus(data) {
  if (!data) return null;
  if (data.status === "not_configured") {
    return unavailableCard("Respaldo", data, "La ruta de respaldo no esta configurada.");
  }
  if (unavailable(data) || data.exists == null || (data.exists && (data.days_since_last_backup == null || data.latest_size == null))) {
    return unavailableCard("Respaldo", data);
  }
  const ok = data.exists === true && Number(data.days_since_last_backup) <= 7 && Number(data.latest_size) > 0;
  return {
    title: "Respaldo",
    label: ok ? "Reciente" : "Revisar",
    detail: data.exists ? `Ultimo respaldo hace ${data.days_since_last_backup ?? "sin dato"} dias.` : "No se encontro respaldo valido.",
    level: ok ? "ok" : "high",
    items: data.latest_file ? [`Archivo: ${data.latest_file}`, `Tamano: ${data.latest_size || 0} bytes`] : [],
  };
}
