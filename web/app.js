import { dashboardModules, renderModule } from "/static/modules/dashboardModules.js";
import { escapeHtml } from "/static/modules/utils.js";
import { icon } from "/static/modules/icons.js";

import { deviceHeartbeats, eventRows, isSerious } from "/static/modules/events.js";

const state = {
  dashboard: null, ai: null, user: null, users: null, audit: null, install: null, activeModule: "computadoras",
  live: { events: [], latestId: 0, unseen: 0 },
  deviceNotice: null,
};

// Live feed: poll only for events newer than the last one seen.
async function pollLive() {
  const response = await fetch(`/api/events?after_id=${state.live.latestId}&limit=100`).catch(() => null);
  if (!response || !response.ok) return;
  const data = await response.json();
  const fresh = data.events || [];
  const first = state.live.latestId === 0;
  if (fresh.length) {
    state.live.events = [...fresh, ...state.live.events].slice(0, 200);
    state.live.latestId = data.latest_id;
    if (!first && state.activeModule !== "envivo") {
      state.live.unseen += fresh.filter(isSerious).length;
      renderModuleTabs();
    }
  }
  if (state.activeModule === "envivo") {
    state.live.unseen = 0;
    const feed = document.getElementById("liveFeed");
    if (feed) feed.innerHTML = eventRows(state.live.events);
    const count = document.getElementById("liveCount");
    if (count) count.textContent = `${state.live.events.length} aviso(s)`;
    const heartbeats = document.getElementById("liveHeartbeats");
    if (heartbeats) heartbeats.innerHTML = deviceHeartbeats(state.dashboard?.devices || []);
  }
}

async function ensureSession() {
  const response = await fetch("/api/me");
  if (response.status === 401) {
    window.location.href = "/login";
    return false;
  }
  state.user = await response.json();
  const role = state.user.role_label || state.user.role;
  const company = state.user.company_name || "";
  document.getElementById("currentUser").innerHTML = `<strong>${escapeHtml(state.user.username)}</strong><span>${escapeHtml([role, company].filter(Boolean).join(" · "))}</span>`;
  document.getElementById("userAvatar").textContent = (company || state.user.username || "?").trim().charAt(0) || "?";
  if (company) document.getElementById("pageEyebrow").textContent = company;
  const fromHash = window.location.hash.slice(1);
  if (dashboardModules(state.user).some(([id]) => id === fromHash)) state.activeModule = fromHash;
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

const moduleIcons = {
  computadoras: "monitor", envivo: "activity", analista: "chat", estado: "shield", problemas: "alert",
  revisiones: "search", historial: "history", tareas: "tasks", usuarios: "users", auditoria: "audit",
};

function gradeFor(score) {
  if (score == null) return null;
  return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
}

const gradeWords = { A: "Muy bien protegido", B: "Bien, con detalles por mejorar", C: "Regular: hay cosas importantes por corregir", D: "En riesgo", F: "En alto riesgo" };

function metricCard(label, value, iconName, tone, hot = false) {
  return `<div class="metric tone-${tone}${hot ? " is-hot" : ""}">
    <div class="metric-top"><span class="metric-label">${escapeHtml(label)}</span><i class="metric-icon">${icon(iconName)}</i></div>
    <strong>${escapeHtml(value)}</strong>
  </div>`;
}

function renderMetrics() {
  const { devices, findings, scans, summary } = state.dashboard;
  const openFindings = findings.filter((finding) => finding.status !== "resolved");
  const metrics = summary || {};
  const score = metrics.security_score;
  const grade = gradeFor(score);
  const scoreCard = `<div class="metric metric-score">
    <div class="score-ring ${grade ? `ring-${grade}` : ""}" style="--value:${Number(score) || 0}"><span>${grade || "-"}</span></div>
    <div>
      <span class="metric-label">Puntaje de seguridad</span>
      <strong>${score == null ? "-" : `${escapeHtml(score)}/100`}</strong>
      <span class="metric-hint">${grade ? escapeHtml(gradeWords[grade]) : "Aún sin revisiones completas"}</span>
    </div>
  </div>`;
  const critical = metrics.critical ?? 0;
  document.getElementById("metrics").innerHTML = scoreCard + [
    ["Computadoras", metrics.devices ?? devices.length, "monitor", "primary"],
    ["Conectadas ahora", metrics.online_devices ?? 0, "wifi", "ok"],
    ["Problemas por resolver", metrics.open_findings ?? openFindings.length, "flag", "primary"],
    ["Urgentes (hoy)", critical, "octagon", "bad", critical > 0],
    ["Importantes (esta semana)", metrics.high ?? 0, "alert", "warn"],
    ["Revisar pronto", metrics.medium ?? 0, "info", "info"],
    ["Ya corregidos", metrics.resolved ?? 0, "check", "ok"],
    ["Revisiones", scans.length, "search", "neutral"],
  ].map(([label, value, iconName, tone, hot]) => metricCard(label, value, iconName, tone, hot)).join("");
}

function renderModuleTabs() {
  const modules = dashboardModules(state.user);
  document.getElementById("moduleTabs").innerHTML = modules.map(([id, label]) => `
    <button class="tab ${state.activeModule === id ? "active" : ""}" data-module="${id}">${icon(moduleIcons[id])}<span>${escapeHtml(label)}</span>${id === "envivo" && state.live.unseen ? `<span class="tab-alert">${state.live.unseen}</span>` : ""}</button>
  `).join("");
  const active = modules.find(([id]) => id === state.activeModule);
  if (active) {
    document.getElementById("pageTitle").textContent = active[1];
    document.title = `${active[1]} - CyberCheck MIPYME`;
  }
  document.querySelectorAll("[data-module]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.activeModule = button.dataset.module;
      history.replaceState(null, "", `#${state.activeModule}`);
      if (state.activeModule === "envivo") state.live.unseen = 0;
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
  document.querySelectorAll(".delete-btn").forEach((button) => {
    button.addEventListener("click", () => deleteDevice(button.dataset.deviceId, button.dataset.deviceName));
  });
  document.querySelectorAll(".reactivate-btn").forEach((button) => {
    button.addEventListener("click", () => reactivateDevice(button.dataset.deviceId));
  });
  document.querySelectorAll(".rotate-btn").forEach((button) => {
    button.addEventListener("click", () => rotateCredential(button.dataset.deviceId));
  });
  const addDeviceBtn = document.getElementById("addDeviceBtn");
  if (addDeviceBtn) addDeviceBtn.addEventListener("click", downloadInstaller);
  if (state.install) renderInstallNotice();
  renderDeviceNotice();
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

// Device action results live in state so dashboard re-renders keep them.
function showDeviceNotice(html) {
  state.deviceNotice = html;
  renderDeviceNotice();
}

function renderDeviceNotice() {
  const notice = document.getElementById("reconnectNotice");
  if (!notice || !state.deviceNotice) return;
  notice.hidden = false;
  notice.innerHTML = state.deviceNotice;
}

async function deviceAction(path, method = "POST") {
  try {
    return await postJson(path, undefined, method);
  } catch (error) {
    showDeviceNotice(`<span class="error">${escapeHtml(error.message)}</span>`);
    return null;
  }
}

async function reconnectDevice(deviceId) {
  showDeviceNotice("Revisando la conexion...");
  const data = await deviceAction(`/api/devices/${encodeURIComponent(deviceId)}/reconnect`);
  if (!data) return;
  const steps = (data.steps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("");
  showDeviceNotice(`<strong>${data.agent_status === "online" ? "Agente conectado" : "Estado de la conexion"}</strong><p>${escapeHtml(data.message || "")}</p>${steps ? `<ol class="install-steps">${steps}</ol>` : ""}`);
}

async function deleteDevice(deviceId, name) {
  if (!window.confirm(`Eliminar "${name}" del sistema? Se borraran sus problemas, revisiones y eventos. Esta accion no se puede deshacer.`)) return;
  showDeviceNotice("Eliminando computadora...");
  const data = await deviceAction(`/api/devices/${encodeURIComponent(deviceId)}`, "DELETE");
  if (!data) return;
  showDeviceNotice(`<strong>Computadora eliminada</strong><p>${escapeHtml(data.message)}</p>`);
  await loadDashboard();
}

async function disconnectDevice(deviceId) {
  if (!window.confirm("Desconectar este agente? El token quedara desactivado y se cancelaran solicitudes pendientes.")) return;
  showDeviceNotice("Desconectando agente...");
  const data = await deviceAction(`/api/devices/${encodeURIComponent(deviceId)}/disconnect`);
  if (!data) return;
  showDeviceNotice(`<strong>Agente desconectado</strong><p>${escapeHtml(data.message)}</p>`);
  await loadDashboard();
}

async function reactivateDevice(deviceId) {
  showDeviceNotice("Reactivando agente...");
  const data = await deviceAction(`/api/devices/${encodeURIComponent(deviceId)}/reactivate`);
  if (!data) return;
  showDeviceNotice(`<strong>Agente reactivado</strong><p>${escapeHtml(data.message)}</p>`);
  await loadDashboard();
}

// --- Agregar computadora -------------------------------------------------
// The installer download carries a company-bound enrollment token in its
// file name; the page then waits until the new device reports in.

function renderInstallNotice() {
  const notice = document.getElementById("installNotice");
  if (!notice || !state.install) return;
  const { phase, message, device } = state.install;
  notice.hidden = false;
  notice.classList.toggle("detected", phase === "detected");
  if (phase === "downloading") {
    notice.innerHTML = "<strong>Preparando el instalador...</strong><p>La primera descarga puede tardar unos segundos.</p>";
  } else if (phase === "error") {
    notice.innerHTML = `<strong>No se pudo descargar el instalador</strong><p class="error">${escapeHtml(message)}</p>`;
  } else if (phase === "waiting") {
    notice.innerHTML = `
      <strong>Instalador descargado</strong>
      <ol class="install-steps">
        <li>Abre <strong>CyberCheckSetup</strong> en la computadora que quieres proteger (puedes copiarlo por USB o correo interno).</li>
        <li>Acepta el permiso de administrador de Windows. Si aparece "Windows protegio su PC", elige <em>Mas informacion &gt; Ejecutar de todas formas</em>.</li>
        <li>Listo: el equipo aparecera aqui solo. No cambies el nombre del archivo.</li>
      </ol>
      <p class="muted">Esperando que la computadora se conecte...</p>`;
  } else if (phase === "detected") {
    notice.innerHTML = `<strong>Computadora conectada: ${escapeHtml(device)}</strong><p>Su primera revision de seguridad ya esta en camino.</p>`;
  }
}

async function downloadInstaller() {
  const baseline = new Set((state.dashboard?.devices || []).map((device) => device.device_id));
  state.install = { phase: "downloading" };
  renderInstallNotice();
  try {
    const response = await fetch("/api/agent/installer");
    if (response.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || `Error ${response.status}`);
    }
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="?([^";]+)"?/);
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = match ? match[1] : "CyberCheckSetup.exe";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 60_000);
  } catch (error) {
    state.install = { phase: "error", message: error.message };
    renderInstallNotice();
    return;
  }
  state.install = { phase: "waiting" };
  renderInstallNotice();
  waitForNewDevice(baseline);
}

async function waitForNewDevice(baseline) {
  const deadline = Date.now() + 30 * 60_000;
  while (state.install?.phase === "waiting" && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 8_000));
    const response = await fetch("/api/dashboard").catch(() => null);
    if (!response || !response.ok) continue;
    const dashboard = await response.json();
    const added = dashboard.devices.find((device) => !baseline.has(device.device_id));
    if (added) {
      state.dashboard = dashboard;
      state.install = { phase: "detected", device: added.name || added.hostname || added.device_id };
      render();
      return;
    }
  }
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

// Links such as /#problemas also work while the panel is already open.
window.addEventListener("hashchange", async () => {
  const target = window.location.hash.slice(1);
  if (!state.user || !state.dashboard || target === state.activeModule) return;
  if (!dashboardModules(state.user).some(([id]) => id === target)) return;
  state.activeModule = target;
  if (target === "envivo") state.live.unseen = 0;
  renderModuleTabs();
  renderActiveModule();
  await loadModuleData();
  renderActiveModule();
});

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});

ensureSession().then((ok) => {
  if (!ok) return;
  loadDashboard();
  pollLive();
  setInterval(() => {
    if (!document.hidden) pollLive();
  }, 5_000);
});

setInterval(() => {
  if (!document.hidden) loadDashboard();
}, 60_000);
