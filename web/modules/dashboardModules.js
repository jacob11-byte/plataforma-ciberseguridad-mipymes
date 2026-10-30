import { escapeHtml } from "./utils.js";
import { taskLabels, taskLabel, statusLabel } from "./labels.js";
import { latestStatusEvidence, renderSecurityStatus } from "./securityStatus.js";
import { findingCard, latestEvidenceByDeviceAndControl } from "./findings.js";
import { can, roleLabels } from "./roles.js";
import { deviceHeartbeats, eventRows } from "./events.js";

const allModules = [
  ["computadoras", "Computadoras", "viewer"],
  ["envivo", "En vivo", "viewer"],
  ["analista", "Analista de evidencia", "viewer"],
  ["estado", "Estado", "viewer"],
  ["problemas", "Problemas", "viewer"],
  ["revisiones", "Revisiones", "viewer"],
  ["historial", "Historial", "viewer"],
  ["tareas", "Tareas", "viewer"],
  ["usuarios", "Usuarios", "admin"],
  ["auditoria", "Auditoria", "admin"],
];

export function dashboardModules(user) {
  return allModules.filter(([, , role]) => can(user, role)).map(([id, label]) => [id, label]);
}

const renderers = {
  computadoras: renderDevicesModule,
  envivo: renderLiveModule,
  analista: renderAiModule,
  estado: renderSecurityModule,
  problemas: renderFindingsModule,
  revisiones: renderScansModule,
  historial: renderHistoryModule,
  tareas: renderTasksModule,
  usuarios: renderUsersModule,
  auditoria: renderAuditModule,
};

export function renderModule(moduleId, state) {
  return (renderers[moduleId] || renderDevicesModule)(state);
}

function renderDevicesModule(state) {
  const { devices } = state.dashboard;
  const canInstall = can(state.user, "technician");
  return `
    <div class="section-title">
      <h2>Computadoras</h2>
      <div class="row-actions">
        ${canInstall ? `<button id="addDeviceBtn" type="button">+ Agregar computadora</button>` : ""}
        ${canInstall ? taskFormHtml(devices) : ""}
      </div>
    </div>
    <div id="installNotice" class="notice" hidden></div>
    <p class="empty-state" ${devices.length ? "hidden" : ""}>Aun no hay computadoras registradas.${canInstall ? " Pulsa <strong>Agregar computadora</strong>, abre el archivo descargado en el equipo y aparecera aqui automaticamente." : ""}</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Computadora</th><th>Seguridad</th><th>Sistema</th><th>Agente</th><th>Ultimo contacto</th><th>Accion</th></tr></thead>
        <tbody>${devices.map((device) => deviceRow(device, state.user)).join("")}</tbody>
      </table>
    </div>
    <div id="reconnectNotice" class="notice" hidden></div>
  `;
}

function renderLiveModule(state) {
  const live = state.live;
  return `
    <div class="section-title">
      <div>
        <h2><span class="live-dot"></span> En vivo</h2>
        <p>Lo que está pasando ahora en tus computadoras. Se actualiza solo cada 5 segundos.</p>
      </div>
      <span class="muted" id="liveCount">${live.events.length} aviso(s)</span>
    </div>
    <div id="liveHeartbeats">${deviceHeartbeats(state.dashboard?.devices || [])}</div>
    <details class="live-help" ${live.events.length ? "" : "open"}>
      <summary>¿Qué aparece aquí?</summary>
      <p>Cada computadora protegida avisa en segundos cuando pasa algo importante para su seguridad, por ejemplo:</p>
      <ul>
        <li>Alguien intenta adivinar una contraseña.</li>
        <li>Se conecta una memoria USB.</li>
        <li>El antivirus encuentra un virus, o alguien lo apaga.</li>
        <li>Se crea una cuenta nueva o alguien recibe permisos de administrador.</li>
        <li>Se abre un programa sospechoso o un programa empieza a aceptar conexiones de la red.</li>
      </ul>
      <p>Si la lista está vacía, es buena señal: no ha pasado nada raro. <strong>¿Quieres probarlo?</strong> Conecta una memoria USB a una computadora protegida y en menos de un minuto aparecerá aquí.</p>
    </details>
    <h3>Avisos</h3>
    <div id="liveFeed" class="live-feed">${eventRows(live.events)}</div>
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

function deviceActions(device, user) {
  const id = escapeHtml(device.device_id);
  const actions = [];
  if (can(user, "technician")) {
    actions.push(`<button class="small secondary reconnect-btn" data-device-id="${id}">Reconectar</button>`);
  }
  if (can(user, "admin")) {
    actions.push(`<button class="small secondary rotate-btn" data-device-id="${id}">Rotar credencial</button>`);
    actions.push(`<button class="small secondary reactivate-btn" data-device-id="${id}">Reactivar</button>`);
    actions.push(`<button class="small secondary danger disconnect-btn" data-device-id="${id}">Desconectar</button>`);
    actions.push(`<button class="small secondary danger delete-btn" data-device-id="${id}" data-device-name="${escapeHtml(device.name || device.hostname || device.device_id)}">Eliminar</button>`);
  }
  return actions.length ? `<div class="row-actions">${actions.join("")}</div>` : `<span class="muted">Solo lectura</span>`;
}

function deviceRow(device, user) {
  return `
    <tr>
      <td><a class="device-link" href="/devices/${encodeURIComponent(device.device_id)}"><strong>${escapeHtml(device.name || device.hostname || device.device_id)}</strong></a><div class="muted">${escapeHtml(device.device_id)}</div></td>
      <td><span class="grade-pill grade-${escapeHtml(device.security_grade || "na")}">${escapeHtml(device.security_grade || "-")}</span> ${escapeHtml(device.security_score ?? "-")}/100<div class="muted">${escapeHtml(device.security_open_findings ?? 0)} problema(s) abierto(s)</div></td>
      <td>${escapeHtml(device.windows_edition || device.os_version || "Sin dato")}<div class="muted">${escapeHtml(device.architecture || "")}</div></td>
      <td><span class="status ${device.agent_status}">${statusLabel(device.agent_status, device.agent_status_label || "Sin conexion")}</span><div class="muted">${escapeHtml(device.agent_version || "sin version")}</div></td>
      <td>${escapeHtml(device.last_seen || "Sin contacto")}</td>
      <td>${deviceActions(device, user)}</td>
    </tr>
  `;
}

function renderAiModule(state) {
  const ai = state.ai || {};
  return `
    <div class="section-title">
      <div>
        <h2>Analista de evidencia</h2>
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
  const names = Object.fromEntries((state.dashboard.devices || []).map((d) => [d.device_id, d.name || d.hostname || ""]));
  const order = { Critico: 0, Alto: 1, Medio: 2, Bajo: 3 };
  const ordered = [...findings].sort((a, b) =>
    (a.status === "resolved") - (b.status === "resolved") || (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  return `
    <div class="section-title">
      <div>
        <h2>Problemas encontrados</h2>
        <p>Del más urgente al menos urgente. Cada uno explica qué pasa, por qué importa y qué hacer.</p>
      </div>
      <span>${openFindings.length} por resolver</span>
    </div>
    <div class="findings">
      ${ordered.length ? ordered.map((finding) => {
        const evidenceControl = finding.rule_id.startsWith("WAZUH:") ? `wazuh_cve:${finding.rule_id}` : finding.control;
        return findingCard(finding, latestEvidence[`${finding.device_id}:${evidenceControl}`], names[finding.device_id]);
      }).join("") : `<p class="empty-state">Aún no hay problemas. Cuando una computadora termine su revisión, aquí verás lo que haya que mejorar.</p>`}
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
      ${task.delivery_attempts ? `<div class="muted">Intentos de entrega: ${escapeHtml(task.delivery_attempts)}</div>` : ""}
      ${task.last_error ? `<div class="error">${escapeHtml(task.last_error)}</div>` : ""}
      <div class="muted">${escapeHtml(task.created_at)}</div>
    </div>
  `).join("") || `<p class="empty-state">Sin solicitudes enviadas.</p>`}</div>`;
}

function roleOptions(selected) {
  return Object.entries(roleLabels).map(([value, label]) =>
    `<option value="${value}" ${value === selected ? "selected" : ""}>${escapeHtml(label)}</option>`).join("");
}

function renderUsersModule(state) {
  const data = state.users;
  if (!data) return `<h2>Usuarios</h2><p class="empty-state">Cargando usuarios...</p>`;
  const rows = data.users.map((user) => `
    <tr>
      <td><strong>${escapeHtml(user.username)}</strong><div class="muted">Ultimo acceso: ${escapeHtml(user.last_login_at || "nunca")}</div></td>
      <td><select class="user-role" data-user-id="${user.id}" ${user.username === state.user.username ? "disabled" : ""}>${roleOptions(user.role)}</select></td>
      <td><span class="badge ${user.active ? "ok" : "failed"}">${user.active ? "Activo" : "Desactivado"}</span></td>
      <td>
        <div class="row-actions">
          <input type="password" class="user-password" data-user-id="${user.id}" placeholder="Nueva contrasena" autocomplete="new-password">
          <button class="small secondary user-password-btn" data-user-id="${user.id}">Cambiar</button>
          ${user.username === state.user.username ? "" : `<button class="small ${user.active ? "danger" : "secondary"} user-active-btn" data-user-id="${user.id}" data-active="${user.active ? "false" : "true"}">${user.active ? "Desactivar" : "Activar"}</button>`}
        </div>
      </td>
    </tr>
  `).join("");
  return `
    <div class="section-title">
      <div>
        <h2>Usuarios</h2>
        <p>${data.bootstrap_admin ? `El administrador inicial <strong>${escapeHtml(data.bootstrap_admin)}</strong> se configura con variables de entorno.` : "Invita a tu equipo con su correo y una contrasena inicial."}</p>
      </div>
      <form id="userForm">
        <input id="newUsername" placeholder="usuario" autocomplete="off" required>
        <input id="newPassword" type="password" placeholder="Contrasena (12+ caracteres)" autocomplete="new-password" required>
        <select id="newRole">${roleOptions("viewer")}</select>
        <button type="submit">Crear usuario</button>
      </form>
    </div>
    <div id="userNotice" class="notice" hidden></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Usuario</th><th>Rol</th><th>Estado</th><th>Acciones</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="4" class="empty-state">Aun no hay usuarios adicionales.</td></tr>`}</tbody>
      </table>
    </div>
  `;
}

const auditLabels = {
  "login.success": "Inicio de sesion",
  "login.failure": "Inicio de sesion fallido",
  logout: "Cierre de sesion",
  "task.create": "Revision solicitada",
  "device.register": "Equipo registrado",
  "device.disconnect": "Equipo desconectado",
  "device.delete": "Equipo eliminado",
  "device.reactivate": "Equipo reactivado",
  "device.rotation_requested": "Rotacion de credencial solicitada",
  "device.credential_rotated": "Credencial del agente renovada",
  "password.reset": "Contrasena restablecida",
  "password.reset_requested": "Recuperacion de contrasena solicitada",
  "account.signup": "Cuenta creada",
  "installer.download": "Instalador descargado",
  "installer.revoke": "Instaladores invalidados",
  "user.create": "Usuario creado",
  "user.update": "Usuario modificado",
};

function renderAuditModule(state) {
  const events = state.audit;
  if (!events) return `<h2>Auditoria</h2><p class="empty-state">Cargando eventos...</p>`;
  const rows = events.map((event) => `
    <tr>
      <td>${escapeHtml(event.created_at)}</td>
      <td>${escapeHtml(event.actor)}</td>
      <td><span class="badge ${event.action === "login.failure" ? "failed" : "ok"}">${escapeHtml(auditLabels[event.action] || event.action)}</span></td>
      <td>${escapeHtml([event.target_type, event.target_id].filter(Boolean).join(": "))}</td>
      <td class="muted">${escapeHtml(Object.keys(event.details || {}).length ? JSON.stringify(event.details) : "")}</td>
    </tr>
  `).join("");
  return `
    <div class="section-title">
      <div>
        <h2>Auditoria</h2>
        <p>Acciones administrativas y de agentes, de la mas reciente a la mas antigua.</p>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Fecha</th><th>Actor</th><th>Accion</th><th>Objetivo</th><th>Detalle</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="empty-state">Sin eventos registrados.</td></tr>`}</tbody>
      </table>
    </div>
  `;
}
