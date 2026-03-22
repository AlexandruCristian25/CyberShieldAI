import uuid
import time
from flask import Flask, request, g, jsonify
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from utils import logger
from config import Config
from middleware import attach_user_from_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # === Configurare CORS sigur ===
    cors_origins = app.config.get("CORS_ORIGINS", ["https://yourdomain.com"])
    CORS(app, origins=cors_origins, supports_credentials=True)

    # === Rate Limiter Global ===
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # === Secure Headers după fiecare răspuns ===
    @app.after_request
    def set_secure_headers(response):
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Request-ID"] = g.get("request_id")
        return response

    # === Middleware de tracking pentru fiecare request ===
    @app.before_request
    def track_request_start():
        g.request_id = str(uuid.uuid4())
        g.start_time = time.time()
        attach_user_from_token()

    @app.after_request
    def track_request_end(response):
        duration = round((time.time() - g.get("start_time", 0)) * 1000, 2)
        logger.log_event(
            f"{request.method} {request.path}",
            context={
                "status": response.status_code,
                "duration_ms": duration,
                "ip": request.remote_addr,
                "request_id": g.get("request_id"),
            }
        )
        return response

    # === Error handling global (inclusiv coduri specifice) ===
    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "Access forbidden"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger.log_error("Unhandled exception", context={
            "error": str(e),
            "path": request.path,
            "ip": request.remote_addr,
            "request_id": g.get("request_id"),
        })
        return jsonify({"error": "Internal server error"}), 500

    # === Modularizare Blueprint-uri ===
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app
