const state = { dashboard: null, ai: null, activeModule: "computadoras" };

const dashboardModules = [
  ["computadoras", "Computadoras"],
  ["analista", "Analista IA"],
  ["estado", "Estado"],
  ["problemas", "Problemas"],
  ["revisiones", "Revisiones"],
  ["historial", "Historial"],
  ["tareas", "Tareas"],
];

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

const statusLabels = {
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
};

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

async function loadDashboard() {
  const response = await fetch("/api/dashboard");
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  state.dashboard = await response.json();
  await loadAiSummary();
  render();
}

async function loadAiSummary() {
  const response = await fetch("/api/ai/company-summary");
  if (response.ok) {
    state.ai = await response.json();
  }
}

function render() {
  const { devices, findings, scans, summary } = state.dashboard;
  const openFindings = findings.filter((f) => f.status !== "resolved");
  const metrics = summary || {};
  document.getElementById("metrics").innerHTML = [
    ["Computadoras", metrics.devices ?? devices.length],
    ["En linea", metrics.online_devices ?? 0],
    ["Problemas abiertos", metrics.open_findings ?? openFindings.length],
    ["Criticos", metrics.critical ?? 0],
    ["Altos", metrics.high ?? 0],
    ["Medios", metrics.medium ?? 0],
    ["Corregidos", metrics.resolved ?? 0],
    ["Revisiones", scans.length],
  ].map(([label, value]) => `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`).join("");
  renderModuleTabs();
  renderActiveModule();
}

function renderModuleTabs() {
  document.getElementById("moduleTabs").innerHTML = dashboardModules.map(([id, label]) => `
    <button class="tab ${state.activeModule === id ? "active" : ""}" data-module="${id}">${escapeHtml(label)}</button>
  `).join("");
  document.querySelectorAll("[data-module]").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeModule = button.dataset.module;
      renderActiveModule();
      renderModuleTabs();
    });
  });
}

function renderActiveModule() {
  const content = document.getElementById("moduleContent");
  const modules = {
    computadoras: renderDevicesModule,
    analista: renderAiModule,
    estado: renderSecurityModule,
    problemas: renderFindingsModule,
    revisiones: renderScansModule,
    historial: renderHistoryModule,
    tareas: renderTasksModule,
  };
  content.innerHTML = (modules[state.activeModule] || renderDevicesModule)();
  attachModuleHandlers();
}

function renderDevicesModule() {
  const { devices } = state.dashboard;
  return `
    <div class="section-title">
      <h2>Computadoras</h2>
      ${taskFormHtml(devices)}
    </div>
    <p id="emptyDevices" class="empty-state" ${devices.length ? "hidden" : ""}>Aun no hay computadoras registradas. Instala el agente en una computadora para comenzar.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Computadora</th><th>Sistema</th><th>Agente</th><th>Ultimo contacto</th><th>Accion</th></tr></thead>
        <tbody id="devices">${devices.map(deviceRow).join("")}</tbody>
      </table>
    </div>
    <div id="reconnectNotice" class="notice" hidden></div>
  `;
}

function taskFormHtml(devices) {
  if (!devices.length) return "";
  return `
    <form id="taskForm">
      <select id="deviceSelect">${devices.map((d) => `<option value="${d.device_id}">${escapeHtml(d.name || d.hostname || d.device_id)}</option>`).join("")}</select>
      <select id="taskType">${Object.entries(taskLabels).map(([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`).join("")}</select>
      <button type="submit">Solicitar revision</button>
    </form>
  `;
}

function deviceRow(d) {
  return `
    <tr>
      <td><a class="device-link" href="/devices/${encodeURIComponent(d.device_id)}"><strong>${escapeHtml(d.name || d.hostname || d.device_id)}</strong></a><div class="muted">${escapeHtml(d.device_id)}</div></td>
      <td>${escapeHtml(d.windows_edition || d.os_version || "Sin dato")}<div class="muted">${escapeHtml(d.architecture || "")}</div></td>
      <td><span class="status ${d.agent_status}">${statusLabel(d.agent_status, d.agent_status_label || "Sin conexion")}</span><div class="muted">${escapeHtml(d.agent_version || "sin version")}</div></td>
      <td>${escapeHtml(d.last_seen || "Sin contacto")}</td>
      <td>
        <div class="row-actions">
          <button class="small secondary reconnect-btn" data-device-id="${escapeHtml(d.device_id)}">Reconectar</button>
          <button class="small secondary reactivate-btn" data-device-id="${escapeHtml(d.device_id)}">Reactivar</button>
          <button class="small danger disconnect-btn" data-device-id="${escapeHtml(d.device_id)}">Desconectar</button>
        </div>
      </td>
    </tr>
  `;
}

function renderAiModule() {
  const ai = state.ai || {};
  return `
    <div class="section-title">
      <div>
        <h2>Analista IA</h2>
        <p>Analisis generado solo con evidencia almacenada en la plataforma.</p>
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
        ${["¿Por que este equipo tiene riesgo alto?", "¿Que cambio desde el ultimo analisis?", "¿Que deberia corregir primero?", "¿Que equipos requieren atencion?"].map((q) => `<button class="small secondary ai-question" data-question="${escapeHtml(q)}">${escapeHtml(q)}</button>`).join("")}
      </div>
      <form id="aiChatForm" class="ai-chat-form">
        <input id="aiQuestion" placeholder="Pregunta sobre la evidencia almacenada">
        <button type="submit">Preguntar</button>
      </form>
      <div id="aiAnswer" class="ai-answer empty-state">La IA respondera solo con evidencia existente.</div>
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

function renderSecurityModule() {
  const latestStatus = latestStatusEvidence(state.dashboard.evidences || []);
  return `
    <div class="section-title">
      <h2>Estado de seguridad</h2>
      <span class="muted">Ultima evidencia real recibida desde la computadora</span>
    </div>
    <div id="securityStatus" class="status-grid">${renderSecurityStatus(latestStatus)}</div>
  `;
}

function renderFindingsModule() {
  const { findings, evidences } = state.dashboard;
  const openFindings = findings.filter((f) => f.status !== "resolved");
  const latestEvidence = latestEvidenceByDeviceAndControl(evidences || []);
  return `
    <div class="section-title">
      <h2>Problemas encontrados</h2>
      <span>${openFindings.length} abiertos</span>
    </div>
    <div id="findings" class="findings">
      ${findings.length ? findings.map((f) => findingCard(f, latestEvidence[`${f.device_id}:${f.control}`])).join("") : `<p class="empty-state">Aun no hay problemas encontrados. Ejecuta una revision para enviar evidencia real.</p>`}
    </div>
  `;
}

function findingCard(f, evidence) {
  return `
    <article class="finding">
      <div class="finding-head">
        <strong>${escapeHtml(f.title)}</strong>
        <span class="badge ${f.status}">${statusLabel(f.status)}</span>
      </div>
      <div><span class="badge ${f.severity}">${escapeHtml(f.severity)}</span> <span class="muted">${escapeHtml(f.control)}</span></div>
      ${renderFindingExplanation(f, evidence)}
      <p>${escapeHtml(f.recommendation)}</p>
      <p class="muted">Cierre: ${escapeHtml(f.closure_criteria)}</p>
      ${renderEvidence(evidence)}
    </article>
  `;
}

function renderScansModule() {
  return `<h2>Revisiones recientes</h2><div class="timeline">${state.dashboard.scans.map((s) => `
    <div class="event"><strong>${taskLabel(s.scan_type)}</strong> en ${escapeHtml(s.device_id)}<div class="muted">${escapeHtml(s.created_at)}</div></div>
  `).join("") || `<p class="empty-state">Sin revisiones registradas.</p>`}</div>`;
}

function renderHistoryModule() {
  return `<h2>Historial de revision</h2><div class="timeline">${state.dashboard.history.map((h) => `
    <div class="event"><strong>${statusLabel(h.previous_status || "nuevo")} -> ${statusLabel(h.new_status)}</strong><div>${escapeHtml(h.note)}</div><div class="muted">${escapeHtml(h.created_at)}</div></div>
  `).join("") || `<p class="empty-state">Sin cambios de estado.</p>`}</div>`;
}

function renderTasksModule() {
  return `<h2>Solicitudes enviadas al agente</h2><div class="timeline">${state.dashboard.tasks.map((t) => `
    <div class="event">
      <strong>${taskLabel(t.task_type)}</strong> en ${escapeHtml(t.device_id)}
      <div><span class="badge ${t.status}">${statusLabel(t.status)}</span></div>
      <div class="muted">${escapeHtml(t.created_at)}</div>
    </div>
  `).join("") || `<p class="empty-state">Sin solicitudes enviadas.</p>`}</div>`;
}

function attachModuleHandlers() {
  document.querySelectorAll(".reconnect-btn").forEach((button) => {
    button.addEventListener("click", () => reconnectDevice(button.dataset.deviceId));
  });
  document.querySelectorAll(".disconnect-btn").forEach((button) => {
    button.addEventListener("click", () => disconnectDevice(button.dataset.deviceId));
  });
  document.querySelectorAll(".reactivate-btn").forEach((button) => {
    button.addEventListener("click", () => reactivateDevice(button.dataset.deviceId));
  });
  const taskForm = document.getElementById("taskForm");
  if (taskForm) taskForm.addEventListener("submit", createTask);
  const aiForm = document.getElementById("aiChatForm");
  if (aiForm) aiForm.addEventListener("submit", askAiFromForm);
  document.querySelectorAll(".ai-question").forEach((button) => {
    button.addEventListener("click", () => askAi(button.dataset.question));
  });
}

function latestEvidenceByDeviceAndControl(evidences) {
  return evidences.reduce((index, item) => {
    const key = `${item.device_id}:${item.control}`;
    if (!index[key]) index[key] = item;
    return index;
  }, {});
}

function latestStatusEvidence(evidences) {
  return evidences.reduce((index, item) => {
    if (!item.control || !item.control.startsWith("status_")) return index;
    const control = item.control.replace("status_", "");
    if (!index[control]) {
      try {
        index[control] = JSON.parse(item.result_json);
      } catch (_error) {
        index[control] = { raw: item.result_json };
      }
    }
    return index;
  }, {});
}

function renderSecurityStatus(status) {
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
  return { title: "Firewall", label: ok ? "Activo" : "Revisar", detail: `Dominio=${yesNo(data.domain)}, Privado=${yesNo(data.private)}, Publico=${yesNo(data.public)}.`, level: ok ? "ok" : "high", items: [] };
}

function updateStatus(data) {
  if (!data) return null;
  const pending = Number(data.pending_count || 0);
  return { title: "Windows Update", label: pending || data.reboot_pending ? "Pendiente" : "Al dia", detail: `${pending} actualizaciones pendientes. Reinicio pendiente=${yesNo(data.reboot_pending)}.`, level: pending || data.reboot_pending ? "medium" : "ok", items: [] };
}

function deviceStatus(data) {
  if (!data) return null;
  const usb = Number(data.usb_storage_count || 0);
  const unsigned = Number(data.unsigned_driver_count || 0);
  const errors = Number(data.device_error_count || 0);
  const level = unsigned ? "high" : (usb || errors ? "medium" : "ok");
  return { title: "Dispositivos conectados", label: level === "ok" ? "Normal" : "Revisar", detail: `${data.device_count || 0} dispositivos revisados, ${usb} USB de almacenamiento, ${unsigned} controladores sin firma, ${errors} con error.`, level, items: (data.usb_storage || []).slice(0, 3).map((item) => `USB: ${item.Model || item.FriendlyName || "Dispositivo"}`) };
}

function portStatus(data) {
  if (!Array.isArray(data)) return null;
  const risky = data.filter((item) => [3389, 5985, 5986, 445, 139].includes(Number(item.port)));
  return { title: "Puertos escuchando", label: risky.length ? "Expuestos" : "Sin riesgo comun", detail: `${data.length} puertos locales escuchando. Riesgo comun detectado: ${risky.length}.`, level: risky.length ? "high" : "ok", items: risky.slice(0, 5).map((item) => `${item.port} ${item.process_name || ""}`.trim()) };
}

function backupStatus(data) {
  if (!data) return null;
  const ok = data.exists === true && Number(data.days_since_last_backup || 999) <= 7;
  return { title: "Respaldo", label: ok ? "Reciente" : "Revisar", detail: data.exists ? `Ultimo respaldo hace ${data.days_since_last_backup ?? "sin dato"} dias.` : "No se encontro respaldo valido.", level: ok ? "ok" : "high", items: data.latest_file ? [`Archivo: ${data.latest_file}`, `Tamano: ${data.latest_size || 0} bytes`] : [] };
}

function renderEvidence(evidence) {
  if (!evidence) return "";
  let parsed = {};
  try {
    parsed = JSON.parse(evidence.result_json);
  } catch (_error) {
    parsed = { raw: evidence.result_json };
  }
  return `<details class="evidence"><summary>Evidencia tecnica</summary><pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre></details>`;
}

function parseEvidence(evidence) {
  if (!evidence) return {};
  try {
    return JSON.parse(evidence.result_json);
  } catch (_error) {
    return {};
  }
}

function renderFindingExplanation(finding, evidence) {
  const data = parseEvidence(evidence);
  const content = findingNarrative(finding, data);
  return `<div class="finding-explanation"><div><strong>Encontrado:</strong> ${escapeHtml(content.found)}</div><div><strong>Que hacer:</strong> ${escapeHtml(content.action)}</div></div>`;
}

function findingNarrative(finding, data) {
  const rule = finding.rule_id;
  if (rule === "UNAUTHORIZED_LOCAL_ADMIN") return { found: `El grupo Administradores contiene: ${(data.unauthorized_accounts || []).join(", ") || "cuentas no autorizadas"}.`, action: "Abre Administracion de equipos > Usuarios y grupos locales > Grupos > Administradores, y retira las cuentas que no deban tener privilegios." };
  if (rule === "UPDATES_PENDING") return { found: `Windows reporta ${data.pending_count ?? "desconocido"} actualizaciones pendientes. ${data.reboot_pending ? "Tambien hay reinicio pendiente." : "No se reporto reinicio pendiente."}`, action: "Abre Configuracion > Windows Update, instala actualizaciones y reinicia si Windows lo solicita." };
  if (rule === "BACKUP_OLD_OR_MISSING") return { found: data.exists === false ? "No se encontro un respaldo valido en la ruta configurada." : `El ultimo respaldo tiene ${data.days_since_last_backup ?? "edad desconocida"} dias.`, action: "Configura o ejecuta un respaldo reciente y vuelve a solicitar una revision de respaldos." };
  if (rule === "FIREWALL_PUBLIC_DISABLED") return { found: `El perfil Public del firewall esta ${data.public ? "activo" : "desactivado"}.`, action: "Activa el perfil Publico en Seguridad de Windows > Firewall y proteccion de red." };
  if (rule === "USB_STORAGE_CONNECTED") return { found: `Se detectaron ${data.usb_storage_count ?? 0} dispositivos USB de almacenamiento.`, action: "Verifica que el USB sea de confianza y escanealo con antivirus antes de abrir archivos." };
  if (rule === "DEVICE_WITH_ERROR") return { found: `Se detectaron ${data.device_error_count ?? 0} dispositivos con error.`, action: "Revisa el Administrador de dispositivos y corrige o retira el dispositivo con error." };
  return { found: "El motor de reglas encontro una condicion insegura en la evidencia enviada por el agente.", action: finding.recommendation };
}

async function createTask(event) {
  event.preventDefault();
  await fetch("/api/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: document.getElementById("deviceSelect").value, task_type: document.getElementById("taskType").value, parameters: {} }),
  });
  await loadDashboard();
  alert("Revision solicitada. El agente la ejecutara automaticamente cuando haga su proxima conexion.");
}

async function askAiFromForm(event) {
  event.preventDefault();
  const input = document.getElementById("aiQuestion");
  await askAi(input.value);
  input.value = "";
}

async function askAi(question) {
  const answer = document.getElementById("aiAnswer");
  answer.textContent = "Analizando evidencia almacenada...";
  const response = await fetch("/api/ai/company-chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!response.ok) {
    answer.textContent = "No se pudo consultar el Analista IA.";
    return;
  }
  const data = await response.json();
  const refs = (data.evidence_refs || []).map((ref) => `${ref.type} #${ref.id}`).join(", ");
  answer.innerHTML = `<strong>Respuesta:</strong> ${escapeHtml(data.answer)}${refs ? `<div class="muted">Respaldado por: ${escapeHtml(refs)}</div>` : ""}`;
}

async function reconnectDevice(deviceId) {
  const notice = document.getElementById("reconnectNotice");
  notice.hidden = false;
  notice.innerHTML = "Revisando reconexion...";
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/reconnect`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await response.json();
  const commands = (data.commands || []).map((command) => `<pre>${escapeHtml(command)}</pre>`).join("");
  notice.innerHTML = `<strong>Reconectar agente</strong><p>${escapeHtml(data.message || "Ejecuta el comando en el equipo del agente.")}</p>${commands}`;
  await loadDashboard();
}

async function disconnectDevice(deviceId) {
  if (!window.confirm("Desconectar este agente? El token quedara desactivado y se cancelaran solicitudes pendientes.")) return;
  const notice = document.getElementById("reconnectNotice");
  notice.hidden = false;
  notice.innerHTML = "Desconectando agente...";
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/disconnect`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await response.json();
  notice.innerHTML = `<strong>Agente desconectado</strong><p>${escapeHtml(data.message || "El agente fue desconectado.")}</p>`;
  await loadDashboard();
}

async function reactivateDevice(deviceId) {
  const notice = document.getElementById("reconnectNotice");
  notice.hidden = false;
  notice.innerHTML = "Reactivando agente...";
  const response = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/reactivate`, { method: "POST" });
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  const data = await response.json();
  notice.innerHTML = `<strong>Agente reactivado</strong><p>${escapeHtml(data.message || "El agente fue reactivado.")}</p>`;
  await loadDashboard();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function taskLabel(value) {
  return taskLabels[value] || value || "Sin dato";
}

function statusLabel(value, fallback = null) {
  if (fallback && !["online", "offline", "disconnected"].includes(value)) return fallback;
  if (value === "nuevo") return "Nuevo";
  return statusLabels[value] || fallback || value || "Sin dato";
}

function yesNo(value) {
  if (value === true) return "Si";
  if (value === false) return "No";
  if (value === null || value === undefined || value === "") return "sin dato";
  return String(value);
}

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (ok) loadDashboard();
});
