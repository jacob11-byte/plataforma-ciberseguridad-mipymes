export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function parseJson(value, fallback = {}) {
  try {
    return JSON.parse(value);
  } catch (_error) {
    return fallback;
  }
}
