from db import get_db_connection
from logger import log_event, log_error

def get_permissions_from_db(role: str) -> set:
    conn = get_db_connection()
    rows = conn.execute("SELECT action FROM role_permissions WHERE role = ?", (role,)).fetchall()
    return {row["action"] for row in rows}

def has_permission(role: str, action: str) -> bool:
    action = action.strip().lower()
    role = role.strip().lower()

    permissions = get_permissions_from_db(role)
    if action not in permissions:
        log_error(f"[PERMISSION] Unauthorized: role='{role}', action='{action}'")
        return False
    log_event(f"[PERMISSION] Authorized: role='{role}', action='{action}'")
    return True

def grant_permission(role: str, action: str):
    role = role.strip().lower()
    action = action.strip().lower()
    conn = get_db_connection()
    conn.execute("INSERT INTO role_permissions (role, action) VALUES (?, ?)", (role, action))
    conn.commit()
    log_event(f"[PERMISSION] Granted '{action}' to role '{role}'")

def revoke_permission(role: str, action: str):
    role = role.strip().lower()
    action = action.strip().lower()
    conn = get_db_connection()
    conn.execute("DELETE FROM role_permissions WHERE role = ? AND action = ?", (role, action))
    conn.commit()
    log_event(f"[PERMISSION] Revoked '{action}' from role '{role}'")
