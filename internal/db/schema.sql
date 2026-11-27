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

CREATE TABLE IF NOT EXISTS recovery_vaults (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    user_pubkey TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    kdf_alg TEXT NOT NULL,
    kdf_params_json TEXT NOT NULL,
    salt_b64 TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pairing_requests (
    id TEXT PRIMARY KEY,
    oauth_state TEXT NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_user_pubkey TEXT NOT NULL DEFAULT '',
    github_login TEXT NOT NULL DEFAULT '',
    node_name TEXT NOT NULL DEFAULT '',
    os_name TEXT NOT NULL DEFAULT '',
    node_pubkey_b64 TEXT NOT NULL DEFAULT '',
    eph_x25519_pub_b64 TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending_oauth',
    approver_node_id TEXT NOT NULL DEFAULT '',
    approver_eph_x25519_pub_b64 TEXT NOT NULL DEFAULT '',
    approver_signature_b64 TEXT NOT NULL DEFAULT '',
    handoff_nonce_b64 TEXT NOT NULL DEFAULT '',
    encrypted_handoff_b64 TEXT NOT NULL DEFAULT '',
    error_msg TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pairing_requests_target_status
    ON pairing_requests(target_user_pubkey, status, expires_at);
