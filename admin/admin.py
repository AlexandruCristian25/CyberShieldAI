import os
from flask import Flask, request, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
from permissions_dynamic import grant_permission, revoke_permission
from db import get_db_connection
from dotenv import load_dotenv
from audit_log import log_action
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret")

# 🔒 Security Hardening
app.config.update({
    "SESSION_COOKIE_SECURE": True,
    "SESSION_COOKIE_HTTPONLY": True,
    "SESSION_COOKIE_SAMESITE": "Lax",
})

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

# 🔒 Content Security Policy + Headers
@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' https://cdn.tailwindcss.com"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# 🛡️ Admin Panel Route
@app.route("/admin", methods=["GET"])
@limiter.limit("10 per minute")
def admin_panel():
    message = request.args.get("message", "")
    success = request.args.get("success", "") == "True"

    conn = get_db_connection()
    rows = conn.execute("SELECT role, action FROM role_permissions ORDER BY role, action").fetchall()
    permissions = [{"role": row["role"], "action": row["action"]} for row in rows]
    return render_template("admin_permissions.html", permissions=permissions, message=message, success=success)

# 🛡️ Grant Permission
@app.route("/admin/grant", methods=["POST"])
@limiter.limit("10 per minute")
def admin_grant():
    role = escape(request.form.get("role", "").strip())
    action = escape(request.form.get("action", "").strip())

    if role and action:
        grant_permission(role, action)
        log_action("GRANT", role, action, request.remote_addr)
        return redirect(url_for("admin_panel", message=f"✅ Permisiunea '{action}' a fost acordată rolului '{role}'.", success=True))
    else:
        return redirect(url_for("admin_panel", message="❌ Datele trimise nu sunt valide.", success=False))

# 🛡️ Revoke Permission
@app.route("/admin/revoke", methods=["POST"])
@limiter.limit("10 per minute")
def admin_revoke():
    role = escape(request.form.get("role", "").strip())
    action = escape(request.form.get("action", "").strip())

    if role and action:
        revoke_permission(role, action)
        log_action("REVOKE", role, action, request.remote_addr)
        return redirect(url_for("admin_panel", message=f"⚠️ Permisiunea '{action}' a fost revocată pentru rolul '{role}'.", success=True))
    else:
        return redirect(url_for("admin_panel", message="❌ Datele trimise nu sunt valide.", success=False))

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
