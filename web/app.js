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
  const { devices, findings, evidences, scans, tasks, history } = state.dashboard;
  const openFindings = findings.filter((f) => f.status !== "resolved");
  const latestEvidence = latestEvidenceByDeviceAndControl(evidences || []);
  document.getElementById("metrics").innerHTML = [
    ["Equipos", devices.length],
    ["Hallazgos abiertos", openFindings.length],
    ["Analisis", scans.length],
    ["Tareas", tasks.length],
  ].map(([label, value]) => `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`).join("");

  document.getElementById("deviceSelect").innerHTML = devices
    .map((d) => `<option value="${d.device_id}">${d.device_id}</option>`).join("");
  document.getElementById("devices").innerHTML = devices.map((d) => `
    <tr>
      <td><strong>${d.device_id}</strong><div class="muted">${d.name}</div></td>
      <td>${d.os_version || "Sin dato"}<div class="muted">${d.architecture || ""}</div></td>
      <td>${d.last_seen || "Sin contacto"}</td>
      <td>${d.token === "demo-token" ? "demo-token" : "registrado"}</td>
    </tr>
  `).join("");

  document.getElementById("openCount").textContent = `${openFindings.length} abiertos`;
  document.getElementById("findings").innerHTML = findings.length ? findings.map((f) => `
    <article class="finding">
      <div class="finding-head">
        <strong>${f.title}</strong>
        <span class="badge ${f.status}">${f.status}</span>
      </div>
      <div><span class="badge ${f.severity}">${f.severity}</span> <span class="muted">${f.control}</span></div>
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
});

ensureSession().then((ok) => {
  if (ok) {
    loadDashboard();
  }
});
