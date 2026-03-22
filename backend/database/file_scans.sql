-- ========================
-- TABLE: file_scans
-- ========================
CREATE TABLE IF NOT EXISTS file_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    user_id INTEGER,
    scan_engine TEXT,
    is_malicious INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (filename, file_hash)
);

CREATE INDEX IF NOT EXISTS idx_file_scans_hash ON file_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_file_scans_user ON file_scans(user_id);

-- ========================
-- TABLE: audit_log
-- ========================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
    user_id INTEGER,
    action_type TEXT NOT NULL, -- e.g., login, file_scan
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
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_type ON audit_log(action_type);
