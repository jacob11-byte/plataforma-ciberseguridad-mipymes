import { diagnosisBlock, findingTitle } from "/static/modules/findings.js";
import { eventRows } from "/static/modules/events.js";
import { icon } from "/static/modules/icons.js";

const state = { detail: null, ai: null, tab: "resumen", live: { events: [], latestId: 0 } };
const severityOrder = { Critico: 0, Alto: 1, Medio: 2, Bajo: 3 };

const tabGroups = [
  ["General", [
    ["resumen", "Resumen", "gauge"],
    ["hallazgos", "Problemas", "alert"],
    ["vulnerabilidades", "Vulnerabilidades", "bug"],
    ["envivo", "Actividad en vivo", "activity"],
    ["analista", "Analista de evidencia", "chat"],
  ]],
  ["Protección", [
    ["firewall", "Firewall", "brick"],
    ["antivirus", "Antivirus", "shield"],
    ["amenazas", "Amenazas", "octagon"],
    ["updates", "Actualizaciones", "download"],
    ["backups", "Respaldos", "database"],
    ["endurecimiento", "Endurecimiento", "lock"],
    ["detecciones", "Detecciones", "eye"],
  ]],
  ["Equipo", [
    ["sistema", "Informacion del equipo", "monitor"],
    ["inventario", "Inventario", "box"],
    ["software", "Programas", "grid"],
    ["procesos", "Procesos", "cpu"],
    ["puertos", "Puertos", "network"],
    ["servicios", "Servicios remotos", "server"],
    ["administradores", "Administradores", "key"],
    ["dispositivos", "Dispositivos", "usb"],
  ]],
  ["Registros", [
    ["eventlog", "Registro de seguridad", "audit"],
    ["cambios", "Cambios", "diff"],
    ["evidencias", "Evidencias tecnicas", "code"],
    ["historial", "Historial", "history"],
  ]],
];

const statusLabels = {
  PASS: "Correcto",
  WARNING: "Revisar",
  FAIL: "Problema",
  NOT_AVAILABLE: "No disponible",
  NOT_CONFIGURED: "No configurado",
  open: "Abierto",
  reopened: "Reabierto",
  resolved: "Corregido",
  pending: "Pendiente",
  delivered: "Enviado al agente",
  completed: "Completado",
  failed: "Fallo",
  canceled: "Cancelado",
  online: "En linea",
  offline: "Sin conexion",
  disconnected: "Desconectado",
  nuevo: "Nuevo",
  added: "Agregado",
  removed: "Eliminado",
  changed: "Cambiado",
};

const taskLabels = {
  FULL_SCAN: "Revision completa",
  VERIFY_FIREWALL: "Revisar firewall",
  VERIFY_PORTS: "Revisar puertos",
  VERIFY_SERVICES: "Revisar servicios remotos",
  VERIFY_ADMINISTRATORS: "Revisar administradores",
  VERIFY_UPDATES: "Revisar actualizaciones",
  VERIFY_ANTIVIRUS: "Revisar antivirus",
  VERIFY_DEVICES: "Revisar dispositivos",
  VERIFY_BACKUP: "Revisar respaldos",
  V2_SNAPSHOT: "Inventario completo",
  VERIFY_SECURITY_CONTROLS: "Revisar controles de seguridad",
  VERIFY_SOFTWARE: "Revisar programas instalados",
  VERIFY_PROCESSES: "Revisar procesos activos",
  VERIFY_EVENTLOG: "Revisar eventos de seguridad",
};

const columnLabels = {
  address: "Direccion",
  port: "Puerto",
  process_id: "PID",
  process_name: "Proceso",
  name: "Nombre",
  version: "Version",
  publisher: "Fabricante",
  install_date: "Fecha de instalacion",
  signature_status: "Firma digital",
  signer: "Firmado por",
  executable_path: "Ruta del ejecutable",
  time_created: "Fecha",
  event_id: "Evento",
  provider: "Origen",
  level: "Nivel",
  machine: "Computadora",
  status: "Estado",
  start_type: "Inicio",
  running: "En ejecucion",
  Model: "Modelo",
  Size: "Tamano",
  MediaType: "Tipo",
  InterfaceType: "Interfaz",
  Class: "Clase",
  FriendlyName: "Nombre",
  Status: "Estado",
  Manufacturer: "Fabricante",
  ThreatName: "Amenaza",
  SeverityID: "Severidad",
  CategoryID: "Categoria",
  DidThreatExecute: "Se ejecuto",
  IsActive: "Activa",
  path: "Ruta",
  change: "Cambio",
  before: "Antes",
  after: "Despues",
  scan_type: "Tipo de revision",
  task_type: "Solicitud",
  created_at: "Fecha",
  completed_at: "Completado",
  delivered_at: "Enviado",
  duration_ms: "Duracion",
  modules_success: "Modulos correctos",
  modules_error: "Modulos con error",
};

function deviceIdFromPath() {
  return decodeURIComponent(window.location.pathname.split("/").filter(Boolean).at(-1) || "");
}

async function ensureSession() {
  const response = await fetch("/api/me");
  if (response.status === 401) {
    window.location.href = "/login";
    return false;
  }
  const data = await response.json();
  const role = data.role_label || data.role;
  document.getElementById("currentUser").innerHTML = `<strong>${escapeHtml(data.username)}</strong><span>${escapeHtml([role, data.company_name].filter(Boolean).join(" · "))}</span>`;
  document.getElementById("userAvatar").textContent = (data.company_name || data.username || "?").trim().charAt(0) || "?";
  // Device credential actions are admin-only; the API enforces it too.
  const isAdmin = data.role === "admin";
  document.getElementById("reactivateBtn").hidden = !isAdmin;
  document.getElementById("disconnectBtn").hidden = !isAdmin;
  document.getElementById("deleteBtn").hidden = !isAdmin;
  return true;
}

async function loadDetail() {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/detail`);
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  state.detail = await response.json();
  await loadDeviceAi();
  render();
}

async function loadDeviceAi() {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/ai-summary`);
  if (response.ok) {
    state.ai = await response.json();
  }
}

function render() {
  const { device, summary } = state.detail;
  document.getElementById("deviceTitle").textContent = device.name || device.hostname || device.device_id;
  document.getElementById("deviceSubtitle").textContent = `${device.windows_edition || device.os_version || "Sistema no evaluado"} - ${device.agent_status_label || "Sin conexion"}`;
  const scoreTone = { A: "ok", B: "ok", C: "warn", D: "bad", F: "bad" }[summary.security_grade] || "primary";
  document.getElementById("deviceMetrics").innerHTML = [
    ["Puntaje de seguridad", summary.security_score == null ? "No evaluado" : `${summary.security_score}/100 (${summary.security_grade})`, "shield", scoreTone],
    ["Ultima conexion", summary.last_heartbeat || "No evaluado", "wifi", "primary"],
    ["Version del agente", summary.agent_version || "No evaluado", "box", "neutral"],
    ["Ultima revision completa", summary.last_full_scan?.created_at || "No evaluado", "search", "primary"],
    ["Duracion", formatDuration(summary.last_scan_duration_ms), "clock", "neutral"],
    ["Modulos correctos", valueOrNA(summary.modules_success), "check", "ok"],
    ["Modulos error", valueOrNA(summary.modules_error), "alert", Number(summary.modules_error) > 0 ? "warn" : "neutral"],
    ["Controles correctos", summary.controls_pass, "shield", "ok"],
    ["Problemas abiertos", summary.open_findings, "flag", Number(summary.open_findings) > 0 ? "bad" : "ok"],
  ].map(([label, value, iconName, tone]) => `<div class="metric tone-${tone}"><div class="metric-top"><span class="metric-label">${escapeHtml(label)}</span><i class="metric-icon">${icon(iconName)}</i></div><strong>${escapeHtml(value)}</strong></div>`).join("");

  document.getElementById("tabs").innerHTML = tabGroups.map(([group, items]) => `
    <div class="nav-group">${escapeHtml(group)}</div>
    ${items.map(([id, label, iconName]) => `
      <button class="tab ${state.tab === id ? "active" : ""}" data-tab="${id}">${icon(iconName)}<span>${escapeHtml(label)}</span></button>
    `).join("")}
  `).join("");
  document.querySelectorAll("#tabs .tab").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.tab;
      render();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });
  document.getElementById("tabContent").innerHTML = renderTab();
  attachTabHandlers();
}

function attachTabHandlers() {
  document.querySelectorAll("[data-goto-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.gotoTab;
      render();
    });
  });
  const aiForm = document.getElementById("aiChatForm");
  if (aiForm) {
    aiForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const input = document.getElementById("aiQuestion");
      await askDeviceAi(input.value);
      input.value = "";
    });
  }
  document.querySelectorAll(".ai-question").forEach((button) => {
    button.addEventListener("click", () => askDeviceAi(button.dataset.question));
  });
}

async function askDeviceAi(question) {
  const answer = document.getElementById("aiAnswer");
  if (!answer) return;
  answer.textContent = "Analizando evidencia almacenada...";
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/ai-chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    answer.textContent = "No se pudo consultar el analista de evidencia.";
    return;
  }
  const data = await response.json();
  const refs = (data.evidence_refs || []).map((ref) => `${ref.type} #${ref.id}`).join(", ");
  answer.innerHTML = `<strong>Respuesta:</strong> ${escapeHtml(data.answer)}${refs ? `<div class="muted">Respaldado por: ${escapeHtml(refs)}</div>` : ""}`;
}

function renderTab() {
  const data = state.detail;
  if (state.tab === "resumen") return renderSummary(data);
  if (state.tab === "vulnerabilidades") return renderVulnerabilities(data);
  if (state.tab === "envivo") return renderLive();
  if (state.tab === "analista") return renderAiTab();
  if (state.tab === "sistema") return renderObject("Informacion del equipo", controlData("system_info"));
  if (state.tab === "inventario") return renderModuleObject("Inventario avanzado", controlData("system_inventory_v2"));
  if (state.tab === "firewall") return renderObject("Firewall", controlData("firewall"));
  if (state.tab === "puertos") return renderPorts(controlData("ports"));
  if (state.tab === "servicios") return renderServices(controlData("services"));
  if (state.tab === "administradores") return renderAdministrators(controlData("administrators"));
  if (state.tab === "updates") return renderObject("Actualizaciones", controlData("updates"));
  if (state.tab === "antivirus") return renderObject("Antivirus", controlData("antivirus"));
  if (state.tab === "amenazas") return renderThreats(controlData("threats"));
  if (state.tab === "backups") return renderObject("Respaldos", controlData("backup"));
  if (state.tab === "dispositivos") return renderDevices(controlData("connected_devices"));
  if (state.tab === "software") return renderModuleTable("Programas instalados", controlData("software_inventory"), ["name", "version", "publisher", "install_date"]);
  if (state.tab === "procesos") return renderModuleTable("Procesos activos", controlData("process_inventory"), ["process_id", "name", "signature_status", "signer", "executable_path"]);
  if (state.tab === "eventlog") return renderModuleTable("Registro de seguridad permitido", controlData("security_eventlog"), ["time_created", "event_id", "provider", "level", "machine"]);
  if (state.tab === "endurecimiento") return renderModuleObject("Endurecimiento del sistema", controlData("hardening"));
  if (state.tab === "detecciones") return renderDetections(controlData("security_detections"));
  if (state.tab === "cambios") return renderDiffs(data.diffs);
  if (state.tab === "hallazgos") return renderFindings(data.findings);
  if (state.tab === "evidencias") return renderEvidences(data.evidences);
  if (state.tab === "historial") return renderHistory(data.history);
  return noEvaluado();
}

function renderAiTab() {
  const ai = state.ai || {};
  return `
    <div class="section-title">
      <div>
        <h2>Analista de evidencia</h2>
        <p>Analisis basado solamente en evidencia almacenada de esta computadora.</p>
      </div>
      <span class="badge ${ai.insufficient_evidence ? "medium" : "ok"}">${escapeHtml(ai.risk_level || "sin evidencia")}</span>
    </div>
    <div class="ai-grid">
      ${aiCard("Resumen IA", ai.summary || "No existe evidencia suficiente para determinarlo.")}
      ${aiListCard("Prioridades", (ai.priorities || []).map((item) => `${item.title}: ${item.recommendation}`))}
      ${aiListCard("Cambios relevantes", ai.changes || [])}
      ${aiListCard("Posibles anomalias", ai.anomalies || [])}
      ${aiListCard("Recomendaciones", ai.recommendations || [])}
    </div>
    <section class="ai-chat">
      <h3>Chat contextual</h3>
      <div class="quick-questions">
        ${["¿Por que este equipo tiene riesgo alto?", "¿Que cambio desde el ultimo analisis?", "¿Que deberia corregir primero?"].map((q) => `<button class="small secondary ai-question" data-question="${escapeHtml(q)}">${escapeHtml(q)}</button>`).join("")}
      </div>
      <form id="aiChatForm" class="ai-chat-form">
        <input id="aiQuestion" placeholder="Pregunta sobre esta computadora">
        <button type="submit">Preguntar</button>
      </form>
      <div id="aiAnswer" class="ai-answer empty-state">El analista responde solo con evidencia almacenada.</div>
    </section>
  `;
}

function aiCard(title, content) {
  return `<article class="status-card ok"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(content)}</p></article>`;
}

function aiListCard(title, items) {
  const list = items.length ? `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : `<p>No existe evidencia suficiente para determinarlo.</p>`;
  return `<article class="status-card medium"><strong>${escapeHtml(title)}</strong>${list}</article>`;
}

function controlData(name) {
  return state.detail.controls[name]?.data;
}

function openFindingsBySeverity(findings) {
  return findings
    .filter((finding) => finding.status !== "resolved")
    .sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
}

function renderSummary(data) {
  const urgent = openFindingsBySeverity(data.findings).slice(0, 5);
  const issues = data.collection_issues || [];
  const grade = data.summary.security_grade;
  return `
    <section class="score-panel grade-${escapeHtml(grade || "na")}">
      <div class="score-value">
        <strong>${data.summary.security_score ?? "-"}</strong><span>/100</span>
        <em>Nota ${escapeHtml(grade || "-")}</em>
      </div>
      <div>
        <h2>Lo que hay que atender primero</h2>
        ${urgent.length ? `<ol class="urgent-list">${urgent.map((finding) => `
          <li>
            <span class="urgency sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.diagnosis?.plain?.urgency || finding.severity)}</span>
            <strong>${escapeHtml(findingTitle(finding))}</strong>
            ${finding.diagnosis?.plain?.what ? `<div class="muted">${escapeHtml(finding.diagnosis.plain.what)}</div>` : ""}
          </li>`).join("")}</ol>` : `<p class="muted">No hay problemas por resolver en la última revisión.</p>`}
        ${urgent.length ? `<button type="button" class="small secondary" data-goto-tab="hallazgos">Ver qué hacer con cada uno</button>` : ""}
      </div>
    </section>
    ${issues.length ? `
      <section class="notice">
        <strong>Controles que no se pudieron verificar en la ultima revision</strong>
        <ul class="issue-list">${issues.map((issue) => `
          <li><strong>${escapeHtml(issue.label)}:</strong> ${escapeHtml(issue.error)}<div class="muted">${escapeHtml(issue.hint)}</div></li>
        `).join("")}</ul>
      </section>` : ""}
    <div class="control-matrix">
      ${data.control_matrix.map((item) => `
        <article class="control-tile ${item.status}">
          <strong>${escapeHtml(item.label)}</strong>
          <span class="state ${item.status}">${escapeHtml(labelValue(item.status))}</span>
          <div class="muted">${escapeHtml(item.last_seen || "No evaluado")}</div>
        </article>
      `).join("")}
    </div>
    <div class="grid detail-grid">
      ${renderInfoCard("Ultima solicitud enviada", data.summary.last_requested_task)}
      ${renderInfoCard("Ultima solicitud completada", data.summary.last_completed_task)}
      ${renderInfoCard("Ultima revision", data.summary.last_scan)}
      ${renderInfoCard("Ultima revision completa", data.summary.last_full_scan)}
    </div>
  `;
}

function renderObject(title, data) {
  if (!data) return noEvaluado(title);
  return `<h2>${escapeHtml(title)}</h2>${keyValueTable(data)}`;
}

function renderModuleObject(title, moduleResult) {
  if (!moduleResult) return noEvaluado(title);
  const data = unwrapModule(moduleResult);
  return `
    <h2>${escapeHtml(title)}</h2>
    ${moduleHeader(moduleResult)}
    ${data ? keyValueTable(data) : noEvaluado()}
  `;
}

function renderModuleTable(title, moduleResult, columns) {
  if (!moduleResult) return noEvaluado(title);
  const rows = unwrapModule(moduleResult);
  return `
    <h2>${escapeHtml(title)}</h2>
    ${moduleHeader(moduleResult)}
    ${Array.isArray(rows) && rows.length ? table(columns, rows) : `<p class="muted">No evaluado o sin registros.</p>`}
  `;
}

function moduleHeader(moduleResult) {
  if (!moduleResult || !Object.prototype.hasOwnProperty.call(moduleResult, "success")) return "";
  return `
    <div class="module-header">
      <span class="state ${moduleResult.success ? "PASS" : "FAIL"}">${moduleResult.success ? "Correcto" : "Error"}</span>
      <span class="muted">${escapeHtml(moduleResult.collected_at || "Sin fecha")} - ${escapeHtml(formatDuration(moduleResult.duration_ms))}</span>
      ${moduleResult.error ? `<span class="error">${escapeHtml(moduleResult.error)}</span>` : ""}
    </div>
  `;
}

function unwrapModule(moduleResult) {
  if (moduleResult && Object.prototype.hasOwnProperty.call(moduleResult, "data")) {
    return moduleResult.data;
  }
  return moduleResult;
}

function renderPorts(rows) {
  if (!Array.isArray(rows)) return noEvaluado("Puertos");
  return table(["address", "port", "process_id", "process_name"], rows);
}

function renderServices(rows) {
  if (!Array.isArray(rows)) return noEvaluado("Servicios remotos");
  return table(["name", "status", "start_type", "running"], rows);
}

function renderAdministrators(rows) {
  if (!Array.isArray(rows)) return noEvaluado("Administradores");
  return `<ul class="plain-list">${rows.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderThreats(data) {
  if (!data) return noEvaluado("Amenazas");
  const threats = data.threats || [];
  return `
    <h2>Amenazas</h2>
    <p>Amenazas activas: <strong>${escapeHtml(data.active_threat_count ?? 0)}</strong></p>
    ${threats.length ? table(["ThreatName", "SeverityID", "CategoryID", "DidThreatExecute", "IsActive"], threats) : `<p class="muted">No hay amenazas reportadas.</p>`}
  `;
}

function renderDevices(data) {
  if (!data) return noEvaluado("Dispositivos");
  return `
    <div class="status-grid">
      ${renderMiniStat("Dispositivos", data.device_count)}
      ${renderMiniStat("USB almacenamiento", data.usb_storage_count)}
      ${renderMiniStat("Drivers sin firma", data.unsigned_driver_count)}
      ${renderMiniStat("Con error", data.device_error_count)}
    </div>
    <h2>USB de almacenamiento</h2>
    ${Array.isArray(data.usb_storage) && data.usb_storage.length ? table(["Model", "Size", "MediaType", "InterfaceType"], data.usb_storage) : `<p class="muted">No evaluado o sin USB de almacenamiento.</p>`}
    <h2>Dispositivos con error</h2>
    ${Array.isArray(data.device_errors) && data.device_errors.length ? table(["Class", "FriendlyName", "Status", "Manufacturer"], data.device_errors) : `<p class="muted">Sin dispositivos con error.</p>`}
    <h2>Dispositivos presentes</h2>
    ${Array.isArray(data.devices) && data.devices.length ? table(["Class", "FriendlyName", "Status", "Manufacturer"], data.devices) : noEvaluado()}
  `;
}

function renderFindings(rows) {
  const ordered = [...openFindingsBySeverity(rows), ...rows.filter((finding) => finding.status === "resolved")];
  return ordered.length ? `<div class="findings">${ordered.map((finding) => `
    <article class="finding sev-${escapeHtml(finding.severity)} ${finding.status === "resolved" ? "is-resolved" : ""}">
      <div class="finding-head"><strong>${escapeHtml(findingTitle(finding))}</strong><span class="badge ${finding.status}">${escapeHtml(labelValue(finding.status))}</span></div>
      ${diagnosisBlock(finding, `<p class="muted">Se da por corregido cuando: ${escapeHtml(finding.closure_criteria)} (regla ${escapeHtml(finding.rule_id)})</p>`)
        || `<p>${escapeHtml(finding.recommendation)}</p>`}
    </article>
  `).join("")}</div>` : `<p class="empty-state">Sin problemas registrados.</p>`;
}

function renderVulnerabilities(data) {
  const rows = data.vulnerabilities || [];
  const exploited = rows.filter((row) => row.kev);
  const nvd = (cve) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer">${escapeHtml(cve)}</a>`;
  return `
    <div class="section-title">
      <div>
        <h2>Vulnerabilidades detectadas</h2>
        <p>Parches de Windows pendientes (con sus CVE segun Windows Update), programas instalados con fallas conocidas y programas sin soporte. Se marcan las que ya se explotan en ataques reales (catalogo CISA KEV y boletin de seguridad de Microsoft).</p>
      </div>
      <span class="badge ${exploited.length ? "Critico" : "ok"}">${rows.length} en total · ${exploited.length} explotadas activamente</span>
    </div>
    ${data.kev_loaded || data.msrc_loaded ? "" : `<div class="notice">Los catalogos de explotacion (CISA KEV y boletin de Microsoft) aun no estan cargados en el servidor; no se puede afirmar cuales vulnerabilidades se estan explotando.</div>`}
    ${rows.length ? `<div class="table-wrap"><table>
      <thead><tr><th>CVE</th><th>Producto</th><th>Instalado</th><th>Corregido en</th><th>Origen</th><th>Estado</th></tr></thead>
      <tbody>${rows.map((row) => `
        <tr class="${row.kev ? "kev-row" : ""}">
          <td>${row.cve ? nvd(row.cve) : "Sin CVE (sin soporte)"}<div class="muted">${escapeHtml(row.summary || "")}</div></td>
          <td>${escapeHtml(row.product || "")}</td>
          <td>${escapeHtml(row.installed || "-")}</td>
          <td>${escapeHtml(row.fixed_in || "sin correccion")}</td>
          <td>${escapeHtml(row.source)}</td>
          <td>${row.kev ? `<span class="badge Critico">EXPLOTADA ACTIVAMENTE</span> <span class="muted">${escapeHtml((row.exploited_by || []).join(" + "))}</span>${row.ransomware ? ` <span class="badge Alto">ransomware</span>` : ""}` : `<span class="muted">sin explotacion conocida</span>`}</td>
        </tr>`).join("")}</tbody>
    </table></div>` : `<p class="empty-state">No se detectaron vulnerabilidades conocidas en la ultima evidencia. Esto cubre parches de Windows pendientes y los programas de la base curada; no sustituye un escaneo de vulnerabilidades completo.</p>`}
  `;
}

async function pollDeviceLive() {
  if (state.tab !== "envivo" || document.hidden) return;
  const response = await fetch(`/api/events?device_id=${encodeURIComponent(deviceIdFromPath())}&after_id=${state.live.latestId}&limit=100`).catch(() => null);
  if (!response || !response.ok) return;
  const data = await response.json();
  if (data.events.length) {
    state.live.events = [...data.events, ...state.live.events].slice(0, 200);
    state.live.latestId = data.latest_id;
  }
  const feed = document.getElementById("liveFeed");
  if (feed) feed.innerHTML = eventRows(state.live.events, false);
}

function renderLive() {
  pollDeviceLive();
  return `
    <div class="section-title">
      <div>
        <h2><span class="live-dot"></span> Actividad en vivo de este equipo</h2>
        <p>Avisos al momento: intentos de adivinar contraseñas, memorias USB, virus o antivirus apagado, cuentas nuevas y programas sospechosos. Se actualiza solo cada 5 segundos; si está vacío, no ha pasado nada raro.</p>
      </div>
    </div>
    <div id="liveFeed" class="live-feed">${eventRows(state.live.events, false)}</div>
  `;
}

function renderDetections(rows) {
  const events = Array.isArray(rows) ? rows : [];
  if (!rows) return noEvaluado("Detecciones");
  const labels = {
    4625: "Inicio de sesion fallido", 4720: "Cuenta creada", 4726: "Cuenta eliminada",
    4732: "Agregado a grupo local", 4740: "Cuenta bloqueada", 1102: "Registro de seguridad borrado",
    7045: "Servicio instalado",
  };
  return `
    <h2>Eventos de seguridad relevantes (ultimas 24 h)</h2>
    ${events.length ? table(["time_created", "evento", "target_user", "source_ip", "subject_user", "service_name", "image_path"],
      events.map((event) => ({ ...event, evento: `${event.event_id} - ${labels[event.event_id] || ""}` })))
      : `<p class="muted">Sin eventos sospechosos en las ultimas 24 horas.</p>`}
  `;
}

function renderEvidences(rows) {
  return rows.length ? rows.map((row) => `
    <details class="evidence" open>
      <summary>${escapeHtml(row.control)} - ${escapeHtml(taskLabel(row.scan_type))} - ${escapeHtml(row.created_at)}</summary>
      <pre>${escapeHtml(JSON.stringify(parseJson(row.result_json), null, 2))}</pre>
    </details>
  `).join("") : noEvaluado("Evidencias");
}

function renderHistory(rows) {
  return rows.length ? rows.map((row) => `
    <div class="event">
      <strong>${escapeHtml(labelValue(row.previous_status || "nuevo"))} -> ${escapeHtml(labelValue(row.new_status))}</strong>
      <div>${escapeHtml(row.note)}</div>
      <div class="muted">${escapeHtml(row.created_at)}</div>
    </div>
  `).join("") : `<p class="muted">Sin historial.</p>`;
}

function renderDiffs(rows) {
  return rows.length ? rows.map((row) => {
    const diff = parseJson(row.diff_json);
    const changes = diff.changes || [];
    return `
      <article class="status-card medium">
        <strong>Snapshot ${escapeHtml(row.previous_snapshot_id)} -> ${escapeHtml(row.current_snapshot_id)}</strong>
        <p>${escapeHtml(row.created_at)} - ${escapeHtml(diff.summary?.total_changes ?? 0)} cambios</p>
        ${changes.length ? table(["path", "change", "before", "after"], changes.slice(0, 50)) : `<p class="muted">Sin cambios.</p>`}
      </article>
    `;
  }).join("") : `<p class="muted">Sin cambios entre snapshots.</p>`;
}

function keyValueTable(data) {
  return `<div class="table-wrap"><table><tbody>${Object.entries(data).map(([key, value]) => `
    <tr><th>${escapeHtml(columnLabel(key))}</th><td>${escapeHtml(formatValue(value, key))}</td></tr>
  `).join("")}</tbody></table></div>`;
}

function table(columns, rows) {
  return `<div class="table-wrap"><table>
    <thead><tr>${columns.map((column) => `<th>${escapeHtml(columnLabel(column))}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((row) => `<tr>${columns.map((column) => `<td>${escapeHtml(formatValue(row[column], column))}</td>`).join("")}</tr>`).join("")}</tbody>
  </table></div>`;
}

function renderInfoCard(title, value) {
  return `<article class="status-card ok"><strong>${escapeHtml(title)}</strong>${value ? keyValueTable(value) : `<p class="muted">No evaluado.</p>`}</article>`;
}

function renderMiniStat(label, value) {
  return `<article class="status-card ok"><strong>${escapeHtml(label)}</strong><p>${escapeHtml(valueOrNA(value))}</p></article>`;
}

function noEvaluado(title = "") {
  return `<p class="muted">${title ? `${escapeHtml(title)}: ` : ""}No evaluado.</p>`;
}

function formatValue(value, key = "") {
  if (value === null || value === undefined || value === "") return "No evaluado";
  if (typeof value === "boolean") return value ? "Si" : "No";
  if (key === "scan_type" || key === "task_type") return taskLabel(value);
  if (key === "status" || key === "change" || key.endsWith("_status")) return labelValue(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function valueOrNA(value) {
  return value === null || value === undefined ? "No evaluado" : String(value);
}

function formatDuration(value) {
  if (value === null || value === undefined) return "No evaluado";
  return `${Math.round(Number(value) / 100) / 10}s`;
}

function parseJson(value) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return { raw: value };
  }
}

function taskLabel(value) {
  return taskLabels[value] || value || "Sin dato";
}

function labelValue(value) {
  return statusLabels[value] || value || "Sin dato";
}

function columnLabel(value) {
  return columnLabels[value] || value.replaceAll("_", " ");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.getElementById("refreshBtn").addEventListener("click", loadDetail);
document.getElementById("reportBtn").addEventListener("click", () => {
  window.open(`/devices/${encodeURIComponent(deviceIdFromPath())}/report`, "_blank");
});
document.getElementById("reactivateBtn").addEventListener("click", async () => {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/reactivate`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    alert(error.detail || "No se pudo reactivar el agente.");
  }
  await loadDetail();
});
document.getElementById("disconnectBtn").addEventListener("click", async () => {
  const confirmed = window.confirm("Desconectar este agente? El token quedara desactivado y se cancelaran solicitudes pendientes.");
  if (!confirmed) return;
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/disconnect`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    alert(error.detail || "No se pudo desconectar el agente.");
  }
  await loadDetail();
});
document.getElementById("deleteBtn").addEventListener("click", async () => {
  const name = state.detail?.device?.name || "este equipo";
  if (!window.confirm(`Eliminar "${name}" del sistema? Se borraran sus problemas, revisiones y eventos. Esta accion no se puede deshacer.`)) return;
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}`, { method: "DELETE" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    alert(error.detail || "No se pudo eliminar la computadora.");
    return;
  }
  window.location.href = "/";
});
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (!ok) return;
  loadDetail();
  setInterval(pollDeviceLive, 5_000);
});
