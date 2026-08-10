import sqlite3
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s"
)

DB_PATH = Path("cybershield_database.db")

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'user', 'guest')) DEFAULT 'user',
    created_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS file_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    filesize INTEGER DEFAULT 0,
    user_id INTEGER,
    scan_engine TEXT DEFAULT 'CyberShield Local Engine',
    is_malicious INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    timestamp DATETIME DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_file_scans_hash ON file_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_file_scans_user ON file_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_file_scans_timestamp ON file_scans(timestamp);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
    user_id INTEGER,
    action_type TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
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
    conn = None

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.executescript(SCHEMA_SQL)

        conn.commit()

        logging.info(
            f"Database {db_path.name} initialized successfully."
        )

    except Exception as e:
        logging.error(
            f"Database initialization failed: {e}"
        )

    finally:
        if conn:
            conn.close()
            logging.info("Database connection closed.")


if __name__ == "__main__":
    init_secure_db()