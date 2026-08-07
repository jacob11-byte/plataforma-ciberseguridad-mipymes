import { escapeHtml, parseJson } from "./utils.js";
import { statusLabel } from "./labels.js";

export function latestEvidenceByDeviceAndControl(evidences) {
  return evidences.reduce((index, item) => {
    const key = `${item.device_id}:${item.control}`;
    if (!index[key]) index[key] = item;
    return index;
  }, {});
}

export function findingCard(finding, evidence) {
  return `
    <article class="finding">
      <div class="finding-head">
        <strong>${escapeHtml(finding.title)}</strong>
        <span class="badge ${finding.status}">${statusLabel(finding.status)}</span>
      </div>
      <div><span class="badge ${finding.severity}">${escapeHtml(finding.severity)}</span> <span class="muted">${escapeHtml(finding.control)}</span></div>
      ${renderFindingExplanation(finding, evidence)}
      <p>${escapeHtml(finding.recommendation)}</p>
      <p class="muted">Cierre: ${escapeHtml(finding.closure_criteria)}</p>
      ${renderEvidence(evidence)}
    </article>
  `;
}

function renderEvidence(evidence) {
  if (!evidence) return "";
  const parsed = parseJson(evidence.result_json, { raw: evidence.result_json });
  return `<details class="evidence"><summary>Evidencia tecnica</summary><pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre></details>`;
}

function renderFindingExplanation(finding, evidence) {
  const data = evidence ? parseJson(evidence.result_json, {}) : {};
  const content = findingNarrative(finding, data);
  return `<div class="finding-explanation"><div><strong>Encontrado:</strong> ${escapeHtml(content.found)}</div><div><strong>Que hacer:</strong> ${escapeHtml(content.action)}</div></div>`;
}

function findingNarrative(finding, data) {
  const rule = finding.rule_id;
  if (rule === "UNAUTHORIZED_LOCAL_ADMIN") {
    return {
      found: `El grupo Administradores contiene: ${(data.unauthorized_accounts || []).join(", ") || "cuentas no autorizadas"}.`,
      action: "Abre Administracion de equipos > Usuarios y grupos locales > Grupos > Administradores, y retira las cuentas que no deban tener privilegios.",
    };
  }
  if (rule === "UPDATES_PENDING") {
    return {
      found: `Windows reporta ${data.pending_count ?? "desconocido"} actualizaciones pendientes. ${data.reboot_pending ? "Tambien hay reinicio pendiente." : "No se reporto reinicio pendiente."}`,
      action: "Abre Configuracion > Windows Update, instala actualizaciones y reinicia si Windows lo solicita.",
    };
  }
  if (rule === "BACKUP_OLD_OR_MISSING") {
    return {
      found: data.exists === false ? "No se encontro un respaldo valido en la ruta configurada." : `El ultimo respaldo tiene ${data.days_since_last_backup ?? "edad desconocida"} dias.`,
      action: "Configura o ejecuta un respaldo reciente y vuelve a solicitar una revision de respaldos.",
    };
  }
  if (rule === "FIREWALL_PUBLIC_DISABLED") {
    return {
      found: `El perfil Public del firewall esta ${data.public ? "activo" : "desactivado"}.`,
      action: "Activa el perfil Publico en Seguridad de Windows > Firewall y proteccion de red.",
    };
  }
  if (rule === "USB_STORAGE_CONNECTED") {
    return {
      found: `Se detectaron ${data.usb_storage_count ?? 0} dispositivos USB de almacenamiento.`,
      action: "Verifica que el USB sea de confianza y escanealo con antivirus antes de abrir archivos.",
    };
  }
  if (rule === "DEVICE_WITH_ERROR") {
    return {
      found: `Se detectaron ${data.device_error_count ?? 0} dispositivos con error.`,
      action: "Revisa el Administrador de dispositivos y corrige o retira el dispositivo con error.",
    };
  }
  return {
    found: "El motor de reglas encontro una condicion insegura en la evidencia enviada por el agente.",
    action: finding.recommendation,
  };
}
