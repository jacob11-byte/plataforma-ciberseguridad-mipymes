const roleLevels = { viewer: 1, technician: 2, admin: 3 };

export const roleLabels = {
  viewer: "Solo lectura",
  technician: "Tecnico",
  admin: "Administrador",
};

// The server enforces every permission; this only hides controls the
// current user cannot use.
export function can(user, minimumRole) {
  return (roleLevels[user?.role] || 0) >= roleLevels[minimumRole];
}
