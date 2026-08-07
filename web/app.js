const state = { dashboard: null };

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
  render();
}

function render() {
  const { devices, findings, evidences, scans, tasks, history, summary } = state.dashboard;
  const openFindings = findings.filter((f) => f.status !== "resolved");
  const latestEvidence = latestEvidenceByDeviceAndControl(evidences || []);
  const latestStatus = latestStatusEvidence(evidences || []);
  const metrics = summary || {};
  document.getElementById("metrics").innerHTML = [
    ["Equipos", metrics.devices ?? devices.length],
    ["En linea", metrics.online_devices ?? 0],
    ["Hallazgos abiertos", metrics.open_findings ?? openFindings.length],
    ["Criticos", metrics.critical ?? 0],
    ["Altos", metrics.high ?? 0],
    ["Medios", metrics.medium ?? 0],
    ["Corregidos", metrics.resolved ?? 0],
    ["Analisis", scans.length],
  ].map(([label, value]) => `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`).join("");

  document.getElementById("deviceSelect").innerHTML = devices
    .map((d) => `<option value="${d.device_id}">${d.device_id}</option>`).join("");
  document.getElementById("taskForm").hidden = devices.length === 0;
  document.getElementById("emptyDevices").hidden = devices.length !== 0;
  document.getElementById("devices").innerHTML = devices.map((d) => `
    <tr>
      <td><strong>${d.name || d.hostname || d.device_id}</strong><div class="muted">${d.device_id}</div></td>
      <td>${d.windows_edition || d.os_version || "Sin dato"}<div class="muted">${d.architecture || ""}</div></td>
      <td><span class="status ${d.agent_status}">${d.agent_status_label || "Sin conexion"}</span><div class="muted">${d.agent_version || "sin version"}</div></td>
      <td>${d.last_seen || "Sin contacto"}</td>
      <td><button class="small secondary reconnect-btn" data-device-id="${escapeHtml(d.device_id)}">Reconectar</button></td>
    </tr>
  `).join("");
  document.querySelectorAll(".reconnect-btn").forEach((button) => {
    button.addEventListener("click", () => reconnectDevice(button.dataset.deviceId));
  });

  document.getElementById("openCount").textContent = `${openFindings.length} abiertos`;
  document.getElementById("securityStatus").innerHTML = renderSecurityStatus(latestStatus);
  document.getElementById("findings").innerHTML = findings.length ? findings.map((f) => `
    <article class="finding">
      <div class="finding-head">
        <strong>${f.title}</strong>
        <span class="badge ${f.status}">${f.status}</span>
      </div>
      <div><span class="badge ${f.severity}">${f.severity}</span> <span class="muted">${f.control}</span></div>
      ${renderFindingExplanation(f, latestEvidence[`${f.device_id}:${f.control}`])}
      <p>${f.recommendation}</p>
      <p class="muted">Cierre: ${f.closure_criteria}</p>
      ${renderEvidence(latestEvidence[`${f.device_id}:${f.control}`])}
    </article>
  `).join("") : `<p class="muted">Aun no hay hallazgos. Ejecuta el agente para enviar evidencia.</p>`;

  document.getElementById("scans").innerHTML = scans.map((s) => `
    <div class="event"><strong>${s.scan_type}</strong> en ${s.device_id}<div class="muted">${s.created_at}</div></div>
  `).join("") || `<p class="muted">Sin analisis registrados.</p>`;

  document.getElementById("history").innerHTML = history.map((h) => `
    <div class="event"><strong>${h.previous_status || "nuevo"} -> ${h.new_status}</strong><div>${h.note}</div><div class="muted">${h.created_at}</div></div>
  `).join("") || `<p class="muted">Sin cambios de estado.</p>`;

  document.getElementById("tasks").innerHTML = tasks.map((t) => `
    <div class="event">
      <strong>${t.task_type}</strong> en ${t.device_id}
      <div><span class="badge ${t.status}">${t.status}</span></div>
      <div class="muted">${t.created_at}</div>
    </div>
  `).join("") || `<p class="muted">Sin tareas solicitadas.</p>`;
}

function latestEvidenceByDeviceAndControl(evidences) {
  return evidences.reduce((index, item) => {
    const key = `${item.device_id}:${item.control}`;
    if (!index[key]) {
      index[key] = item;
    }
    return index;
  }, {});
}

function latestStatusEvidence(evidences) {
  return evidences.reduce((index, item) => {
    if (!item.control || !item.control.startsWith("status_")) {
      return index;
    }
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
    return `<p class="muted">Aun no hay evidencia de estado. Solicita FULL_SCAN o VERIFY_ANTIVIRUS y deja correr el agente.</p>`;
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
    detail: `${data.name || "Antivirus"}: activo=${data.enabled}, tiempo real=${data.real_time}, amenazas activas=${threats}.`,
    level,
    items: [
      `Firmas: ${data.signature_age_days ?? "sin dato"} dias`,
      `Ultimo escaneo rapido: ${data.quick_scan_age_days ?? "sin dato"} dias`,
      `Proteccion contra manipulacion: ${data.tamper_protected ?? "sin dato"}`,
    ],
  };
}

function firewallStatus(data) {
  if (!data) return null;
  const ok = data.domain !== false && data.private !== false && data.public !== false;
  return {
    title: "Firewall",
    label: ok ? "Activo" : "Revisar",
    detail: `Dominio=${data.domain}, Privado=${data.private}, Publico=${data.public}.`,
    level: ok ? "ok" : "high",
    items: [],
  };
}

function updateStatus(data) {
  if (!data) return null;
  const pending = Number(data.pending_count || 0);
  return {
    title: "Windows Update",
    label: pending || data.reboot_pending ? "Pendiente" : "Al dia",
    detail: `${pending} actualizaciones pendientes. Reinicio pendiente=${data.reboot_pending}.`,
    level: pending || data.reboot_pending ? "medium" : "ok",
    items: [],
  };
}

function deviceStatus(data) {
  if (!data) return null;
  const usb = Number(data.usb_storage_count || 0);
  const unsigned = Number(data.unsigned_driver_count || 0);
  const errors = Number(data.device_error_count || 0);
  const level = unsigned ? "high" : (usb || errors ? "medium" : "ok");
  return {
    title: "Dispositivos conectados",
    label: level === "ok" ? "Normal" : "Revisar",
    detail: `${data.device_count || 0} dispositivos revisados, ${usb} USB de almacenamiento, ${unsigned} controladores sin firma, ${errors} con error.`,
    level,
    items: (data.usb_storage || []).slice(0, 3).map((item) => `USB: ${item.Model || item.FriendlyName || "Dispositivo"}`),
  };
}

function portStatus(data) {
  if (!Array.isArray(data)) return null;
  const risky = data.filter((item) => [3389, 5985, 5986, 445, 139].includes(Number(item.port)));
  return {
    title: "Puertos escuchando",
    label: risky.length ? "Expuestos" : "Sin riesgo comun",
    detail: `${data.length} puertos locales escuchando. Riesgo comun detectado: ${risky.length}.`,
    level: risky.length ? "high" : "ok",
    items: risky.slice(0, 5).map((item) => `${item.port} ${item.process_name || ""}`.trim()),
  };
}

function backupStatus(data) {
  if (!data) return null;
  const ok = data.exists === true && Number(data.days_since_last_backup || 999) <= 7;
  return {
    title: "Respaldo",
    label: ok ? "Reciente" : "Revisar",
    detail: data.exists ? `Ultimo respaldo hace ${data.days_since_last_backup ?? "sin dato"} dias.` : "No se encontro respaldo valido.",
    level: ok ? "ok" : "high",
    items: data.latest_file ? [`Archivo: ${data.latest_file}`, `Tamano: ${data.latest_size || 0} bytes`] : [],
  };
}

function renderEvidence(evidence) {
  if (!evidence) {
    return "";
  }
  let parsed = {};
  try {
    parsed = JSON.parse(evidence.result_json);
  } catch (_error) {
    parsed = { raw: evidence.result_json };
  }
  return `
    <details class="evidence">
      <summary>Evidencia tecnica</summary>
      <pre>${escapeHtml(JSON.stringify(parsed, null, 2))}</pre>
    </details>
  `;
}

function parseEvidence(evidence) {
  if (!evidence) {
    return {};
  }
  try {
    return JSON.parse(evidence.result_json);
  } catch (_error) {
    return {};
  }
}

function renderFindingExplanation(finding, evidence) {
  const data = parseEvidence(evidence);
  const content = findingNarrative(finding, data);
  return `
    <div class="finding-explanation">
      <div><strong>Encontrado:</strong> ${escapeHtml(content.found)}</div>
      <div><strong>Que hacer:</strong> ${escapeHtml(content.action)}</div>
    </div>
  `;
}

function findingNarrative(finding, data) {
  const rule = finding.rule_id;
  if (rule === "UNAUTHORIZED_LOCAL_ADMIN") {
    const accounts = (data.unauthorized_accounts || []).join(", ") || "cuentas no autorizadas";
    return {
      found: `El grupo Administradores contiene: ${accounts}.`,
      action: "Abre Administracion de equipos > Usuarios y grupos locales > Grupos > Administradores, y retira las cuentas que no deban tener privilegios.",
    };
  }
  if (rule === "UPDATES_PENDING") {
    const count = data.pending_count ?? "desconocido";
    const reboot = data.reboot_pending ? "Tambien hay reinicio pendiente." : "No se reporto reinicio pendiente.";
    return {
      found: `Windows reporta ${count} actualizaciones pendientes. ${reboot}`,
      action: "Abre Configuracion > Windows Update, instala actualizaciones y reinicia si Windows lo solicita.",
    };
  }
  if (rule === "BACKUP_OLD_OR_MISSING") {
    if (data.exists === false) {
      return {
        found: "No se encontro un respaldo valido en la ruta configurada.",
        action: "Configura una carpeta real de respaldos en el agente o ejecuta un respaldo reciente en la ruta configurada.",
      };
    }
    return {
      found: `El ultimo respaldo tiene ${data.days_since_last_backup ?? "edad desconocida"} dias.`,
      action: "Ejecuta un respaldo nuevo y vuelve a solicitar VERIFY_BACKUP.",
    };
  }
  if (rule === "FIREWALL_PUBLIC_DISABLED") {
    return {
      found: `El perfil Public del firewall esta ${data.public ? "activo" : "desactivado"}.`,
      action: "Abre Seguridad de Windows > Firewall y proteccion de red, activa el perfil Publico y solicita VERIFY_FIREWALL.",
    };
  }
  if (rule === "RDP_EXPOSED") {
    return {
      found: `Puerto 3389 escuchando: ${data.port_3389_listening ? "si" : "no"}. Servicio RDP activo: ${data.termservice_running ? "si" : "no"}.`,
      action: "Desactiva Escritorio remoto si no se usa o restringe el acceso desde el firewall.",
    };
  }
  if (rule === "RISKY_SERVICE_ENABLED") {
    const services = (data.services || []).map((service) => service.name).join(", ") || "servicios remotos";
    return {
      found: `Servicios de riesgo activos: ${services}.`,
      action: "Deten o deshabilita servicios remotos que no sean necesarios.",
    };
  }
  if (rule === "ANTIVIRUS_DISABLED") {
    return {
      found: `Antivirus activo: ${data.enabled}. Proteccion en tiempo real: ${data.real_time}.`,
      action: "Abre Seguridad de Windows y activa Proteccion contra virus y amenazas.",
    };
  }
  if (rule === "ANTIVIRUS_SIGNATURES_OLD") {
    return {
      found: `Firmas con ${data.signature_age_days ?? "edad desconocida"} dias.`,
      action: "Actualiza las firmas desde Seguridad de Windows o Windows Update.",
    };
  }
  if (rule === "ANTIVIRUS_SCAN_OLD") {
    return {
      found: `Ultimo escaneo rapido hace ${data.quick_scan_age_days ?? "tiempo desconocido"} dias.`,
      action: "Ejecuta un analisis rapido o completo y solicita VERIFY_ANTIVIRUS.",
    };
  }
  if (rule === "ANTIVIRUS_ACTIVE_THREATS") {
    return {
      found: `Amenazas activas reportadas: ${data.active_threat_count ?? 0}.`,
      action: "Aplica la accion recomendada por Windows Defender y vuelve a verificar.",
    };
  }
  return {
    found: "El motor de reglas encontro una condicion insegura en la evidencia enviada por el agente.",
    action: finding.recommendation,
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.getElementById("refreshBtn").addEventListener("click", loadDashboard);
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
});
document.getElementById("taskForm").addEventListener("submit", async (event) => {
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
  alert("Tarea creada. El agente la ejecutara automaticamente cuando haga su proxima conexion.");
});

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
  notice.innerHTML = `
    <strong>Reconectar agente</strong>
    <p>${escapeHtml(data.message || "Ejecuta el comando en el equipo del agente.")}</p>
    ${commands}
  `;
  await loadDashboard();
}

ensureSession().then((ok) => {
  if (ok) {
    loadDashboard();
  }
});
