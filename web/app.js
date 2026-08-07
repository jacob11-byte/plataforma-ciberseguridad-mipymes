import { dashboardModules, renderModule } from "/static/modules/dashboardModules.js";
import { escapeHtml } from "/static/modules/utils.js";

const state = { dashboard: null, ai: null, activeModule: "computadoras" };

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
  renderMetrics();
  renderModuleTabs();
  renderActiveModule();
}

function renderMetrics() {
  const { devices, findings, scans, summary } = state.dashboard;
  const openFindings = findings.filter((finding) => finding.status !== "resolved");
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
  ].map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
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
  document.getElementById("moduleContent").innerHTML = renderModule(state.activeModule, state);
  attachModuleHandlers();
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

async function createTask(event) {
  event.preventDefault();
  await fetch("/api/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: document.getElementById("deviceSelect").value,
      task_type: document.getElementById("taskType").value,
      parameters: {},
    }),
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

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (ok) loadDashboard();
});
