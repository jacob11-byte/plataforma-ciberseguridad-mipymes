const state = { detail: null, tab: "resumen" };

const tabs = [
  ["resumen", "Resumen"],
  ["sistema", "Informacion del equipo"],
  ["inventario", "Inventario"],
  ["firewall", "Firewall"],
  ["puertos", "Puertos"],
  ["servicios", "Servicios remotos"],
  ["administradores", "Administradores"],
  ["updates", "Actualizaciones"],
  ["antivirus", "Antivirus"],
  ["amenazas", "Amenazas"],
  ["backups", "Respaldos"],
  ["dispositivos", "Dispositivos"],
  ["software", "Programas"],
  ["procesos", "Procesos"],
  ["eventlog", "Registro de seguridad"],
  ["cambios", "Cambios"],
  ["hallazgos", "Problemas"],
  ["evidencias", "Evidencias tecnicas"],
  ["historial", "Historial"],
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
  document.getElementById("currentUser").textContent = data.username;
  return true;
}

async function loadDetail() {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/detail`);
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  state.detail = await response.json();
  render();
}

function render() {
  const { device, summary } = state.detail;
  document.getElementById("deviceTitle").textContent = device.name || device.hostname || device.device_id;
  document.getElementById("deviceSubtitle").textContent = `${device.windows_edition || device.os_version || "Sistema no evaluado"} - ${device.agent_status_label || "Sin conexion"}`;
  document.getElementById("deviceMetrics").innerHTML = [
    ["Ultima conexion", summary.last_heartbeat || "No evaluado"],
    ["Version del agente", summary.agent_version || "No evaluado"],
    ["Ultima revision completa", summary.last_full_scan?.created_at || "No evaluado"],
    ["Duracion", formatDuration(summary.last_scan_duration_ms)],
    ["Modulos correctos", valueOrNA(summary.modules_success)],
    ["Modulos error", valueOrNA(summary.modules_error)],
    ["Controles correctos", summary.controls_pass],
    ["Problemas abiertos", summary.open_findings],
  ].map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");

  document.getElementById("tabs").innerHTML = tabs.map(([id, label]) => `
    <button class="tab ${state.tab === id ? "active" : ""}" data-tab="${id}">${escapeHtml(label)}</button>
  `).join("");
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.tab;
      render();
    });
  });
  document.getElementById("tabContent").innerHTML = renderTab();
}

function renderTab() {
  const data = state.detail;
  if (state.tab === "resumen") return renderSummary(data);
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
  if (state.tab === "cambios") return renderDiffs(data.diffs);
  if (state.tab === "hallazgos") return renderFindings(data.findings);
  if (state.tab === "evidencias") return renderEvidences(data.evidences);
  if (state.tab === "historial") return renderHistory(data.history);
  return noEvaluado();
}

function controlData(name) {
  return state.detail.controls[name]?.data;
}

function renderSummary(data) {
  return `
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
  return rows.length ? `<div class="findings">${rows.map((finding) => `
    <article class="finding">
      <div class="finding-head"><strong>${escapeHtml(finding.title)}</strong><span class="badge ${finding.status}">${escapeHtml(labelValue(finding.status))}</span></div>
      <div><span class="badge ${finding.severity}">${escapeHtml(finding.severity)}</span> <span class="muted">${escapeHtml(finding.control)}</span></div>
      <p>${escapeHtml(finding.recommendation)}</p>
      <p class="muted">Cierre: ${escapeHtml(finding.closure_criteria)}</p>
    </article>
  `).join("")}</div>` : `<p class="empty-state">Sin problemas registrados.</p>`;
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
document.getElementById("reactivateBtn").addEventListener("click", async () => {
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceIdFromPath())}/reactivate`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
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
  await loadDetail();
});
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (ok) loadDetail();
});
