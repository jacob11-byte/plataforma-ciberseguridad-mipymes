import { escapeHtml } from "./utils.js";
import { taskLabels, taskLabel, statusLabel } from "./labels.js";
import { latestStatusEvidence, renderSecurityStatus } from "./securityStatus.js";
import { findingCard, latestEvidenceByDeviceAndControl } from "./findings.js";

export const dashboardModules = [
  ["computadoras", "Computadoras"],
  ["analista", "Analista IA"],
  ["estado", "Estado"],
  ["problemas", "Problemas"],
  ["revisiones", "Revisiones"],
  ["historial", "Historial"],
  ["tareas", "Tareas"],
];

const renderers = {
  computadoras: renderDevicesModule,
  analista: renderAiModule,
  estado: renderSecurityModule,
  problemas: renderFindingsModule,
  revisiones: renderScansModule,
  historial: renderHistoryModule,
  tareas: renderTasksModule,
};

export function renderModule(moduleId, state) {
  return (renderers[moduleId] || renderDevicesModule)(state);
}

function renderDevicesModule(state) {
  const { devices } = state.dashboard;
  return `
    <div class="section-title">
      <h2>Computadoras</h2>
      ${taskFormHtml(devices)}
    </div>
    <p class="empty-state" ${devices.length ? "hidden" : ""}>Aun no hay computadoras registradas. Instala el agente en una computadora para comenzar.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Computadora</th><th>Sistema</th><th>Agente</th><th>Ultimo contacto</th><th>Accion</th></tr></thead>
        <tbody>${devices.map(deviceRow).join("")}</tbody>
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

function deviceRow(device) {
  return `
    <tr>
      <td><a class="device-link" href="/devices/${encodeURIComponent(device.device_id)}"><strong>${escapeHtml(device.name || device.hostname || device.device_id)}</strong></a><div class="muted">${escapeHtml(device.device_id)}</div></td>
      <td>${escapeHtml(device.windows_edition || device.os_version || "Sin dato")}<div class="muted">${escapeHtml(device.architecture || "")}</div></td>
      <td><span class="status ${device.agent_status}">${statusLabel(device.agent_status, device.agent_status_label || "Sin conexion")}</span><div class="muted">${escapeHtml(device.agent_version || "sin version")}</div></td>
      <td>${escapeHtml(device.last_seen || "Sin contacto")}</td>
      <td>
        <div class="row-actions">
          <button class="small secondary reconnect-btn" data-device-id="${escapeHtml(device.device_id)}">Reconectar</button>
          <button class="small secondary reactivate-btn" data-device-id="${escapeHtml(device.device_id)}">Reactivar</button>
          <button class="small danger disconnect-btn" data-device-id="${escapeHtml(device.device_id)}">Desconectar</button>
        </div>
      </td>
    </tr>
  `;
}

function renderAiModule(state) {
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
        ${["Por que este equipo tiene riesgo alto?", "Que cambio desde el ultimo analisis?", "Que deberia corregir primero?", "Que equipos requieren atencion?"].map((question) => `<button class="small secondary ai-question" data-question="${escapeHtml(question)}">${escapeHtml(question)}</button>`).join("")}
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

function renderSecurityModule(state) {
  const latestStatus = latestStatusEvidence(state.dashboard.evidences || []);
  return `
    <div class="section-title">
      <h2>Estado de seguridad</h2>
      <span class="muted">Ultima evidencia real recibida desde la computadora</span>
    </div>
    <div class="status-grid">${renderSecurityStatus(latestStatus)}</div>
  `;
}

function renderFindingsModule(state) {
  const { findings, evidences } = state.dashboard;
  const openFindings = findings.filter((finding) => finding.status !== "resolved");
  const latestEvidence = latestEvidenceByDeviceAndControl(evidences || []);
  return `
    <div class="section-title">
      <h2>Problemas encontrados</h2>
      <span>${openFindings.length} abiertos</span>
    </div>
    <div class="findings">
      ${findings.length ? findings.map((finding) => findingCard(finding, latestEvidence[`${finding.device_id}:${finding.control}`])).join("") : `<p class="empty-state">Aun no hay problemas encontrados. Ejecuta una revision para enviar evidencia real.</p>`}
    </div>
  `;
}

function renderScansModule(state) {
  return `<h2>Revisiones recientes</h2><div class="timeline">${state.dashboard.scans.map((scan) => `
    <div class="event"><strong>${taskLabel(scan.scan_type)}</strong> en ${escapeHtml(scan.device_id)}<div class="muted">${escapeHtml(scan.created_at)}</div></div>
  `).join("") || `<p class="empty-state">Sin revisiones registradas.</p>`}</div>`;
}

function renderHistoryModule(state) {
  return `<h2>Historial de revision</h2><div class="timeline">${state.dashboard.history.map((item) => `
    <div class="event"><strong>${statusLabel(item.previous_status || "nuevo")} -> ${statusLabel(item.new_status)}</strong><div>${escapeHtml(item.note)}</div><div class="muted">${escapeHtml(item.created_at)}</div></div>
  `).join("") || `<p class="empty-state">Sin cambios de estado.</p>`}</div>`;
}

function renderTasksModule(state) {
  return `<h2>Solicitudes enviadas al agente</h2><div class="timeline">${state.dashboard.tasks.map((task) => `
    <div class="event">
      <strong>${taskLabel(task.task_type)}</strong> en ${escapeHtml(task.device_id)}
      <div><span class="badge ${task.status}">${statusLabel(task.status)}</span></div>
      <div class="muted">${escapeHtml(task.created_at)}</div>
    </div>
  `).join("") || `<p class="empty-state">Sin solicitudes enviadas.</p>`}</div>`;
}
