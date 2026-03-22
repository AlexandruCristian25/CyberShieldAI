from flask import Blueprint, render_template, g, request, abort
from permissions_dynamic import get_permissions_from_db
from logger import log_event
from utils.security import csrf_protect, validate_user_role

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

@dashboard_bp.before_request
def before_dashboard():
    if not getattr(g, "user_authenticated", False):
        abort(403)  # Forbidden
    csrf_protect(request)  # Asigurăm verificare CSRF

@dashboard_bp.route("/", methods=["GET"])
def dashboard_view():
    role = getattr(g, "user_role", None)
    if not validate_user_role(role):
        role = "guest"
        
    try:
        actions = get_permissions_from_db(role)
    except Exception as e:
        log_event("DASHBOARD_PERMISSIONS_ERROR", {"error": str(e), "role": role})
        actions = []

    log_event("DASHBOARD_VIEW", {
        "user_role": role,
        "ip": request.remote_addr,
        "action_count": len(actions)
    })

    response = render_template("dashboard.html", role=role, actions=actions)
    # Add CSP Headers
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self';"
    return response
