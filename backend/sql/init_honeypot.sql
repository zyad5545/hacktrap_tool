-- ملف: backend/sql/init_honeypot.sql
CREATE TABLE IF NOT EXISTS honeypot_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    user_agent TEXT,
    cookies TEXT,
    payload TEXT,
    headers TEXT,
    json_payload TEXT,
    anchored_tx TEXT
);
