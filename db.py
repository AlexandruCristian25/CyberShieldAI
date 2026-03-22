import os
import psycopg2
from contextlib import contextmanager
from config import DB_CONFIG

@contextmanager
def get_db_connection():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute("""
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                security_question TEXT,
                security_answer TEXT,
                twofa_enabled BOOLEAN DEFAULT FALSE,
                twofa_secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                session_token TEXT UNIQUE NOT NULL,
                refresh_token TEXT,
                user_agent TEXT,
                ip_address TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS password_resets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP,
                used BOOLEAN DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                metadata JSONB
            );

            CREATE TABLE IF NOT EXISTS file_uploads (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                status TEXT CHECK (status IN ('clean', 'infected', 'pending')) DEFAULT 'pending',
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                deleted BOOLEAN DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                key TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                message TEXT NOT NULL,
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Indexuri pentru performanță
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
            CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
            CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
            """)

            conn.commit()
            print("[DB INIT] Tabelele au fost create/actualizate cu succes.")
        except Exception as e:
            conn.rollback()
            print(f"[DB INIT ERROR] {str(e)}")
        finally:
            cur.close()

if __name__ == "__main__":
    init_db()
