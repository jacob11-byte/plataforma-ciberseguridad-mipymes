// Progress cards for requested reviews: shows a bar from "sent" to "done"
// without reloading the page, and survives reloads (localStorage).
import { escapeHtml } from "./utils.js";
import { taskLabel } from "./labels.js";

const STORE = "cc-task-watch";
const POLL_MS = 3000;
const PICKUP_SECONDS = 60;    // the agent asks for work about once a minute
const STALE_SECONDS = 600;    // finished long ago: don't pop up after a reload
const STEPS = ["Enviada", "Recibida", "Revisando", "Lista"];

function virusHtml(position) {
  return `<span class="task-virus task-virus-${position}" aria-hidden="true">
    <svg viewBox="0 0 32 32" focusable="false">
      <g fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
        <path d="M16 2v5M16 25v5M2 16h5M25 16h5M6 6l4 4M22 22l4 4M26 6l-4 4M10 22l-4 4"/>
      </g>
      <g fill="currentColor"><circle cx="16" cy="2" r="2"/><circle cx="16" cy="30" r="2"/><circle cx="2" cy="16" r="2"/><circle cx="30" cy="16" r="2"/><circle cx="5.8" cy="5.8" r="1.8"/><circle cx="26.2" cy="26.2" r="1.8"/><circle cx="26.2" cy="5.8" r="1.8"/><circle cx="5.8" cy="26.2" r="1.8"/><circle cx="16" cy="16" r="9"/></g>
      <g class="task-virus-detail"><circle cx="12.5" cy="14" r="1.5"/><circle cx="19.5" cy="17.5" r="1.2"/><circle cx="14" cy="20" r="1"/></g>
    </svg>
  </span>`;
}

function stored() {
  try { return JSON.parse(localStorage.getItem(STORE) || "[]").filter(Number.isInteger); } catch (_error) { return []; }
}

function store(ids) {
  try { localStorage.setItem(STORE, JSON.stringify(ids)); } catch (_error) { /* private mode */ }
}

function clock(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

export function createTaskTracker({ onCompleted, describeResult, onViewProblems } = {}) {
  const root = document.createElement("section");
  root.className = "task-tracker";
  root.setAttribute("aria-live", "polite");
  document.body.appendChild(root);
  const watched = new Map();

  function persist() {
    store([...watched.keys()]);
  }

  function remove(taskId) {
    const entry = watched.get(taskId);
    if (entry) entry.card.remove();
    watched.delete(taskId);
    persist();
  }

  function buildCard(taskId) {
    const card = document.createElement("article");
    card.className = "task-card is-running";
    card.innerHTML = `
      <div class="task-card-head">
        <span class="task-state" aria-hidden="true"></span>
        <div class="task-heading"><strong class="task-title">Solicitando revisión...</strong><span class="task-phase">Enviando la solicitud</span></div>
        <span class="task-time">0:00</span>
        <button type="button" class="task-close" title="Ocultar (la revisión sigue en la computadora)" aria-label="Ocultar">&times;</button>
      </div>
      <div class="task-defense" role="progressbar" aria-label="Progreso de la revisión" aria-valuemin="0" aria-valuemax="100">
        <span class="task-defense-grid" aria-hidden="true"></span>
        ${virusHtml("one")}${virusHtml("two")}${virusHtml("three")}${virusHtml("four")}
        <span class="task-impact" aria-hidden="true"><i></i><i></i><i></i></span>
        <span class="task-defense-core" aria-hidden="true">
          <span class="task-defense-ring"></span>
          <img class="task-defense-shield" src="/static/brand/shield.svg" alt="">
        </span>
        <span class="task-defense-progress"><strong>2%</strong><small>Preparando defensa</small></span>
      </div>
      <ol class="task-steps">${STEPS.map((step) => `<li>${step}</li>`).join("")}</ol>
      <p class="task-note" hidden></p>
      <div class="task-result" hidden></div>`;
    card.querySelector(".task-close").addEventListener("click", () => remove(taskId));
    root.prepend(card);
    return card;
  }

  function watch(taskId) {
    const id = Number(taskId);
    if (!Number.isInteger(id)) return;
    if (!watched.has(id)) {
      watched.set(id, { card: buildCard(id), data: null, polledAt: 0, finished: false, firstPoll: true });
      persist();
    }
    poll(id);
  }

  async function poll(taskId) {
    const entry = watched.get(taskId);
    if (!entry || entry.finished) return;
    const response = await fetch(`/api/tasks/${taskId}`).catch(() => null);
    if (!watched.has(taskId)) return;
    if (response && (response.status === 404 || response.status === 401 || response.status === 403)) {
      remove(taskId);
      return;
    }
    if (!response || !response.ok) return; // network hiccup: keep the last state and retry
    const data = await response.json();
    const finished = ["completed", "failed", "canceled"].includes(data.status);
    if (entry.firstPoll && finished && (data.finished_seconds ?? 0) > STALE_SECONDS) {
      remove(taskId);
      return;
    }
    entry.firstPoll = false;
    entry.data = data;
    entry.polledAt = Date.now();
    if (finished) {
      entry.finished = true;
      if (data.status === "completed" && onCompleted) {
        try { await onCompleted(data); } catch (_error) { /* the card still says it finished */ }
      }
    }
    paint(taskId);
  }

  function progressOf(data, extra) {
    if (data.status === "pending") {
      const waited = (data.waiting_seconds ?? 0) + extra;
      return { percent: Math.min(20, 3 + (waited / PICKUP_SECONDS) * 17), step: 1 };
    }
    if (data.status === "delivered") {
      const ran = (data.running_seconds ?? 0) + extra;
      const ratio = ran / Math.max(5, data.expected_seconds || 60);
      // Ease toward 95% so a slow review never looks finished before it is.
      const percent = ratio < 1 ? 20 + ratio * 70 : 90 + 5 * (1 - Math.exp(-(ratio - 1)));
      return { percent, step: 2, slow: ratio > 1.4 };
    }
    return { percent: 100, step: 4 };
  }

  function paint(taskId) {
    const entry = watched.get(taskId);
    if (!entry || !entry.data) return;
    const { card, data } = entry;
    const extra = entry.finished ? 0 : (Date.now() - entry.polledAt) / 1000;
    const { percent, step, slow } = progressOf(data, extra);
    const offline = !entry.finished && data.agent_status !== "online";
    const failed = data.status === "failed" || data.status === "canceled";

    card.classList.toggle("is-running", !entry.finished);
    card.classList.toggle("is-done", data.status === "completed");
    card.classList.toggle("is-failed", failed);
    card.classList.toggle("is-indeterminate", offline);
    card.dataset.taskStatus = data.status;
    card.querySelector(".task-title").textContent = `${taskLabel(data.task_type)} · ${data.device_name}`;

    const phase = {
      pending: "Esperando que la computadora reciba la solicitud (hasta 1 minuto)",
      delivered: "La computadora se está revisando...",
      completed: "Revisión terminada",
      failed: "La revisión no se pudo completar",
      canceled: "La revisión se canceló",
    }[data.status] || data.status;
    card.querySelector(".task-phase").textContent = phase;

    const elapsed = entry.finished ? null : (data.waiting_seconds ?? 0) + extra;
    card.querySelector(".task-time").textContent = elapsed == null ? "" : clock(elapsed);

    const defense = card.querySelector(".task-defense");
    const roundedPercent = Math.round(percent);
    defense.setAttribute("aria-valuenow", String(roundedPercent));
    defense.style.setProperty("--task-angle", `${Math.max(3, percent * 3.6).toFixed(1)}deg`);
    defense.querySelector("strong").textContent = `${roundedPercent}%`;
    defense.querySelector("small").textContent = offline
      ? "Esperando conexión"
      : data.status === "completed"
        ? "Equipo protegido"
        : failed
          ? "Revisión interrumpida"
          : data.status === "delivered" ? "Neutralizando amenazas" : "Preparando defensa";

    card.querySelectorAll(".task-steps li").forEach((item, index) => {
      item.classList.toggle("done", index < step || data.status === "completed");
      item.classList.toggle("current", index === step && !entry.finished);
    });

    const note = card.querySelector(".task-note");
    const noteText = offline
      ? "La computadora está apagada o sin internet. La revisión empezará sola en cuanto se conecte."
      : failed
        ? (data.error || (data.status === "canceled" ? "La computadora fue desconectada del panel." : "Vuelve a intentarlo en unos minutos."))
        : slow ? "Está tardando un poco más de lo normal; sigue trabajando." : "";
    note.hidden = !noteText;
    note.textContent = noteText;

    const result = card.querySelector(".task-result");
    if (data.status === "completed" && result.hidden) {
      const summary = describeResult ? describeResult(data) : "";
      result.hidden = false;
      result.innerHTML = `${summary ? `<p>${escapeHtml(summary)}</p>` : ""}${onViewProblems ? `<button type="button" class="small secondary task-view">Ver problemas</button>` : ""}`;
      const view = result.querySelector(".task-view");
      if (view) view.addEventListener("click", () => { onViewProblems(data); remove(taskId); });
    }
  }

  setInterval(() => {
    for (const [taskId, entry] of watched) if (!entry.finished) paint(taskId);
  }, 1000);
  setInterval(() => {
    if (document.hidden) return;
    for (const [taskId, entry] of watched) if (!entry.finished) poll(taskId);
  }, POLL_MS);

  stored().forEach(watch);
  return { watch, isWatching: (taskId) => watched.has(Number(taskId)) };
}
