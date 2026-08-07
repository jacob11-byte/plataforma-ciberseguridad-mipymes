export const taskLabels = {
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
  nuevo: "Nuevo",
};

export function taskLabel(value) {
  return taskLabels[value] || value || "Sin dato";
}

export function statusLabel(value, fallback = null) {
  if (fallback && !["online", "offline", "disconnected"].includes(value)) return fallback;
  return statusLabels[value] || fallback || value || "Sin dato";
}

export function yesNo(value) {
  if (value === true) return "Si";
  if (value === false) return "No";
  if (value === null || value === undefined || value === "") return "sin dato";
  return String(value);
}
