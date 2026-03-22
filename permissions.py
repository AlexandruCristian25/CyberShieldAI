from logger import log_error

# Definim permisiuni explicite pe roluri
ROLE_PERMISSIONS = {
    "admin": {"upload", "scan", "view_stats", "manage_users"},
    "moderator": {"upload", "scan", "view_stats"},
    "user": {"upload", "scan"},
    "guest": set()  # fallback default role
}

# Lista acțiunilor valide - protecție suplimentară
VALID_ACTIONS = {
    "upload", "scan", "view_stats", "manage_users"
}

def has_permission(role: str, action: str) -> bool:
    role = role.lower().strip()
    action = action.lower().strip()

    if action not in VALID_ACTIONS:
        log_error(f"Invalid action attempted: '{action}'", context={"role": role})
        return False

    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        log_error(f"Unknown role attempted: '{role}'", context={"action": action})
        return False

    allowed = action in permissions
    if not allowed:
        log_error(f"Unauthorized action: role='{role}', action='{action}'")
    return allowed

# Pentru UI/UX sau debug
def list_permissions(role: str) -> set:
    return ROLE_PERMISSIONS.get(role.lower().strip(), set())
