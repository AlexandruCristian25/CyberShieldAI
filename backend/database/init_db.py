import sqlite3
from pathlib import Path
import logging

# Configurare logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')

# Definim baza de date
DB_PATH = Path("cybershield_database.db")

# Schema bazei de date (mult îmbunătățită)
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT,
    role TEXT CHECK(role IN ('admin', 'user', 'guest')) DEFAULT 'user',
    created_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS file_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    user_id INTEGER,
    scan_engine TEXT,
    is_malicious INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    timestamp DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (filename, file_hash)
);

CREATE INDEX IF NOT EXISTS idx_file_scans_hash ON file_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_file_scans_user ON file_scans(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
    user_id INTEGER,
    action_type TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource TEXT,
    source_ip TEXT,
    user_agent TEXT,
    location TEXT,
    severity_level TEXT DEFAULT 'info',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_type ON audit_log(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
"""

def init_secure_db(db_path=DB_PATH):
    """Initializează baza de date într-un mod securizat."""
    if db_path.exists():
        logging.info(f"📂 Baza de date deja există: {db_path}")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.executescript(SCHEMA_SQL)
        conn.commit()
        logging.info(f"✅ Baza de date {db_path.name} a fost inițializată cu succes.")
    except Exception as e:
        logging.error(f"❌ Eroare la inițializarea bazei de date: {e}")
    finally:
        if conn:
            conn.close()
            logging.info("🔒 Conexiunea la baza de date a fost închisă.")

if __name__ == "__main__":
    init_secure_db()
