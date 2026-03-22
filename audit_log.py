import json
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from logging.handlers import RotatingFileHandler

# === Configurări generale ===
AUDIT_LOG_FILE = "logs/audit.log"
AUDIT_FAILSAFE_FILE = "logs/audit_failed_backup.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# === Setup Logging Rotativ ===
logger = logging.getLogger("audit")
logger.setLevel(logging.INFO)

if not os.path.exists("logs"):
    os.makedirs("logs")

handler = RotatingFileHandler(AUDIT_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(handler)

# === Setup DB Connection via SQLAlchemy ===
DB_URL = os.getenv("SQLITE_URL", "sqlite:///security.db")
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)

# === Funcție principală de Audit ===
def audit(event_type: str, user_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
    metadata = sanitize_metadata(metadata or {})
    timestamp = datetime.utcnow().isoformat()

    log_entry = {
        "timestamp": timestamp,
        "event": sanitize_text(event_type),
        "user_id": user_id,
        "metadata": metadata
    }

    # === Log to file ===
    try:
        logger.info(json.dumps(log_entry))
    except Exception as e:
        logger.warning(f"[Audit] Eroare la log file: {str(e)}")

    # === Log to DB ===
    try:
        session = Session()
        session.execute("""
            INSERT INTO audit_logs (timestamp, event_type, user_id, metadata)
            VALUES (:timestamp, :event_type, :user_id, :metadata)
        """, {
            "timestamp": timestamp,
            "event_type": log_entry["event"],
            "user_id": log_entry["user_id"],
            "metadata": json.dumps(log_entry["metadata"])
        })
        session.commit()
        session.close()
    except Exception as e:
        logger.error(f"[Audit] Eroare la DB: {str(e)}")
        backup_audit_log(log_entry)

# === Funcție de salvare fallback în caz de eșec DB ===
def backup_audit_log(log_entry: Dict[str, Any]) -> None:
    try:
        with open(AUDIT_FAILSAFE_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        logger.critical(f"[Audit] Eroare salvare fallback audit: {str(e)}")

# === Sanitize text input pentru event / metadata keys ===
def sanitize_text(text: str) -> str:
    if not text:
        return ""
    return text.replace("\n", "").replace("\r", "").strip()

# === Sanitize metadata ===
def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    safe_metadata = {}
    for key, value in metadata.items():
        safe_key = sanitize_text(str(key))
        safe_value = sanitize_text(str(value)) if isinstance(value, str) else value
        safe_metadata[safe_key] = safe_value
    return safe_metadata
