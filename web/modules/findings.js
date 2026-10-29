import { escapeHtml, parseJson } from "./utils.js";
import { statusLabel } from "./labels.js";

export function latestEvidenceByDeviceAndControl(evidences) {
  return evidences.reduce((index, item) => {
    const key = `${item.device_id}:${item.control}`;
    if (!index[key]) index[key] = item;
    return index;
  }, {});
}

// Copy buttons for fix commands, wherever a diagnosis is rendered.
document.addEventListener("click", async (event) => {
  const button = event.target.closest?.(".copy-cmd");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.cmd);
    button.textContent = "Copiado";
  } catch (_error) {
    button.textContent = "Selecciona y copia";
  }
  setTimeout(() => { button.textContent = "Copiar"; }, 2000);
});

// What exactly was found, why it is dangerous and how to fix it. Returns ""
// for findings stored before diagnoses existed so callers can fall back.
export function diagnosisBlock(finding) {
  const diagnosis = finding.diagnosis || {};
  if (!diagnosis.detail && !diagnosis.risk) return "";
  const resolved = finding.status === "resolved";
  const steps = diagnosis.steps || [];
  const command = diagnosis.fix_command;
  return `
    <div class="diagnosis">
      ${diagnosis.detail ? `<div class="diag-row"><span class="diag-label">${resolved ? "Ultimo problema detectado" : "Que se encontro"}</span><p>${escapeHtml(diagnosis.detail)}</p></div>` : ""}
      ${diagnosis.risk ? `<div class="diag-row"><span class="diag-label">Por que es peligroso</span><p>${escapeHtml(diagnosis.risk)}</p></div>` : ""}
      ${steps.length || command ? `
        <details class="diag-fix" ${resolved ? "" : "open"}>
          <summary>Como corregirlo</summary>
          ${steps.length ? `<ol>${steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>` : ""}
          ${command ? `
            <div class="fix-command">
              <span class="muted">PowerShell como administrador:</span>
              <code>${escapeHtml(command)}</code>
              <button type="button" class="small secondary copy-cmd" data-cmd="${escapeHtml(command)}">Copiar</button>
            </div>` : ""}
        </details>` : ""}
      ${(diagnosis.references || []).length ? `<div class="diag-refs">${diagnosis.references.map((ref) => `<span class="ref-chip">${escapeHtml(ref)}</span>`).join("")}</div>` : ""}
    </div>
  `;
}

export function findingCard(finding, evidence) {
  const diagnosis = diagnosisBlock(finding);
  return `
    <article class="finding">
      <div class="finding-head">
        <strong>${escapeHtml(finding.title)}</strong>
        <span class="badge ${finding.status}">${statusLabel(finding.status)}</span>
      </div>
      <div><span class="badge ${finding.severity}">${escapeHtml(finding.severity)}</span> <span class="muted">${escapeHtml(finding.device_id || "")}</span></div>
      ${diagnosis || `${renderFindingExplanation(finding, evidence)}<p>${escapeHtml(finding.recommendation)}</p>`}
      <p class="muted">Se cierra cuando: ${escapeHtml(finding.closure_criteria)}</p>
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
  if (rule.startsWith("WAZUH:")) {
    const identity = data.vulnerability_id || "Identificador no disponible";
    const product = data.package_name || "producto no identificado";
    const version = data.package_version ? ` ${data.package_version}` : "";
    const score = data.cvss_score == null ? "sin puntuacion CVSS" : `CVSS ${data.cvss_score}`;
    return {
      found: `Wazuh reporto ${identity} en ${product}${version} (${score}). Fuente: ${data.source || "Wazuh"}.`,
      action: finding.recommendation,
    };
  }
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
