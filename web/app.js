import { dashboardModules, renderModule } from "/static/modules/dashboardModules.js";
import { escapeHtml } from "/static/modules/utils.js";

const state = { dashboard: null, ai: null, user: null, users: null, audit: null, activeModule: "computadoras" };

async function ensureSession() {
  const response = await fetch("/api/me");
  if (response.status === 401) {
    window.location.href = "/login";
    return false;
  }
  state.user = await response.json();
  document.getElementById("currentUser").textContent = `${state.user.username} (${state.user.role_label || state.user.role})`;
  return true;
}

async function postJson(url, body, method = "POST") {
  const response = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Sesion expirada");
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Error ${response.status}`);
  return data;
}

async function loadModuleData() {
  if (state.activeModule === "usuarios") {
    const response = await fetch("/api/users");
    if (response.ok) state.users = await response.json();
  } else if (state.activeModule === "auditoria") {
    const response = await fetch("/api/audit?limit=300");
    if (response.ok) state.audit = (await response.json()).events;
  }
}

async function loadDashboard() {
  const response = await fetch("/api/dashboard");
  if (response.status === 401) {
    window.location.href = "/login";
    return;
  }
  if (!response.ok) {
    document.getElementById("lastUpdated").textContent = "Error al actualizar";
    return;
  }
  state.dashboard = await response.json();
  await Promise.all([loadAiSummary(), loadModuleData()]);
  document.getElementById("lastUpdated").textContent = `Actualizado ${new Date().toLocaleTimeString()}`;
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
  document.getElementById("moduleTabs").innerHTML = dashboardModules(state.user).map(([id, label]) => `
    <button class="tab ${state.activeModule === id ? "active" : ""}" data-module="${id}">${escapeHtml(label)}</button>
  `).join("");
  document.querySelectorAll("[data-module]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.activeModule = button.dataset.module;
      renderActiveModule();
      renderModuleTabs();
      await loadModuleData();
      renderActiveModule();
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
  document.querySelectorAll(".rotate-btn").forEach((button) => {
    button.addEventListener("click", () => rotateCredential(button.dataset.deviceId));
  });
  const userForm = document.getElementById("userForm");
  if (userForm) userForm.addEventListener("submit", createUser);
  document.querySelectorAll(".user-role").forEach((select) => {
    select.addEventListener("change", () => updateUser(select.dataset.userId, { role: select.value }));
  });
  document.querySelectorAll(".user-active-btn").forEach((button) => {
    button.addEventListener("click", () => updateUser(button.dataset.userId, { active: button.dataset.active === "true" }));
  });
  document.querySelectorAll(".user-password-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.querySelector(`.user-password[data-user-id="${button.dataset.userId}"]`);
      if (input && input.value) updateUser(button.dataset.userId, { password: input.value });
    });
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
  const response = await fetch("/api/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: document.getElementById("deviceSelect").value,
      task_type: document.getElementById("taskType").value,
      parameters: {},
    }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    alert(error.detail || "No se pudo solicitar la revision.");
    return;
  }
  const result = await response.json();
  await loadDashboard();
  alert(result.deduplicated
    ? "Ya existia una revision equivalente pendiente; no se creo un duplicado."
    : "Revision solicitada. El agente la ejecutara en su proxima conexion.");
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
    answer.textContent = "No se pudo consultar el analista de evidencia.";
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

function userNotice(message, isError = false) {
  const notice = document.getElementById("userNotice");
  if (!notice) return;
  notice.hidden = false;
  notice.innerHTML = isError ? `<span class="error">${escapeHtml(message)}</span>` : escapeHtml(message);
}

async function createUser(event) {
  event.preventDefault();
  try {
    const user = await postJson("/api/users", {
      username: document.getElementById("newUsername").value,
      password: document.getElementById("newPassword").value,
      role: document.getElementById("newRole").value,
    });
    await loadModuleData();
    renderActiveModule();
    userNotice(`Usuario ${user.username} creado con rol ${user.role_label}.`);
  } catch (error) {
    userNotice(error.message, true);
  }
}

async function updateUser(userId, changes) {
  try {
    const user = await postJson(`/api/users/${encodeURIComponent(userId)}`, changes, "PATCH");
    await loadModuleData();
    renderActiveModule();
    userNotice(`Usuario ${user.username} actualizado. Sus sesiones abiertas fueron cerradas.`);
  } catch (error) {
    await loadModuleData();
    renderActiveModule();
    userNotice(error.message, true);
  }
}

async function rotateCredential(deviceId) {
  const notice = document.getElementById("reconnectNotice");
  notice.hidden = false;
  try {
    const data = await postJson(`/api/devices/${encodeURIComponent(deviceId)}/rotate-credential`);
    notice.innerHTML = `<strong>Rotacion solicitada</strong><p>${escapeHtml(data.message)}</p>`;
  } catch (error) {
    notice.innerHTML = `<span class="error">${escapeHtml(error.message)}</span>`;
  }
}

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (ok) loadDashboard();
});

setInterval(() => {
  if (!document.hidden) loadDashboard();
}, 60_000);
