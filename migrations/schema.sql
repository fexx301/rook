-- Rook SQLite schema

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    cookie_id TEXT UNIQUE NOT NULL,
    honeypot_token TEXT UNIQUE NOT NULL,
    first_ip TEXT,
    first_user_agent TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    agent_probability REAL NOT NULL DEFAULT 0.0,
    is_agent INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    status_code INTEGER,
    user_agent TEXT,
    ip TEXT,
    signals_json TEXT,
    score_delta REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS catches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    request_id INTEGER REFERENCES requests(id),
    timestamp TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    payload_kind TEXT NOT NULL,
    canary TEXT NOT NULL,
    leaked_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_requests_session_time ON requests(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_catches_session ON catches(session_id);
CREATE INDEX IF NOT EXISTS idx_catches_session_time ON catches(session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen_at DESC);
