import json
import os
import logging
from datetime import datetime
from db import get_db_connection
from logging.handlers import RotatingFileHandler

# === Configurăm fallback file logging ===
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "logs/audit.log")
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

logger = logging.getLogger("audit_logger")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)

def safe_json(data):
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        return "{}"

def log_action(action_type: str, role: str, action: str, source_ip: str = "unknown", user_id: int = None):
    timestamp = datetime.utcnow().isoformat()

    # === Înregistrăm în DB ===
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (timestamp, action_type, role, action, source_ip, user_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, action_type, role, action, source_ip, user_id))
        conn.commit()
        conn.close()

    except Exception as e:
        # Dacă DB pică, logăm local
        logger.error(f"[DB_FAIL] Audit event: {safe_json({
            'timestamp': timestamp,
            'action_type': action_type,
            'role': role,
            'action': action,
            'source_ip': source_ip,
            'user_id': user_id,
            'error': str(e)
        })}")

    # === Logăm oricum și local pentru forensic ===
    logger.info(safe_json({
        'timestamp': timestamp,
        'action_type': action_type,
        'role': role,
        'action': action,
        'source_ip': source_ip,
        'user_id': user_id
    }))
