CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_pubkey TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    github_id INTEGER UNIQUE,
    github_login TEXT NOT NULL DEFAULT '',
    github_created_at INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_renewed_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oauth_sessions (
    state TEXT PRIMARY KEY,
    user_pubkey TEXT NOT NULL,
    poll_token_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    cert_token TEXT NOT NULL DEFAULT '',
    error_msg TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS operator_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
