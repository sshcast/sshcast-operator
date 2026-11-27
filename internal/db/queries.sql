-- name: GetUserByPubkey :one
SELECT * FROM users WHERE user_pubkey = ? LIMIT 1;

-- name: GetUserByGitHubID :one
SELECT * FROM users WHERE github_id = ? LIMIT 1;

-- name: InsertUser :one
INSERT INTO users (
    user_pubkey,
    user_id,
    github_id,
    github_login,
    github_created_at,
    status,
    note,
    created_at,
    updated_at,
    last_renewed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpsertManualUser :one
INSERT INTO users (
    user_pubkey,
    user_id,
    github_id,
    github_login,
    github_created_at,
    status,
    note,
    created_at,
    updated_at,
    last_renewed_at
) VALUES (?, ?, NULL, '', 0, 'active', ?, ?, ?, 0)
ON CONFLICT(user_pubkey) DO UPDATE SET
    user_id = excluded.user_id,
    status = 'active',
    updated_at = excluded.updated_at
RETURNING *;

-- name: UpdateUserPubkeyAndLogin :one
UPDATE users
SET user_pubkey = ?, github_login = ?, updated_at = ?
WHERE id = ?
RETURNING *;

-- name: SetUserStatus :one
UPDATE users
SET status = ?, updated_at = ?
WHERE id = ?
RETURNING *;

-- name: TouchUserRenewed :exec
UPDATE users
SET last_renewed_at = ?, updated_at = ?
WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC, id DESC;

-- name: CreateOAuthSession :one
INSERT INTO oauth_sessions (
    state,
    user_pubkey,
    poll_token_hash,
    status,
    cert_token,
    error_msg,
    expires_at,
    created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetOAuthSession :one
SELECT * FROM oauth_sessions WHERE state = ? LIMIT 1;

-- name: UpdateOAuthSession :one
UPDATE oauth_sessions
SET status = ?, cert_token = ?, error_msg = ?
WHERE state = ?
RETURNING *;

-- name: DeleteExpiredOAuthSessions :exec
DELETE FROM oauth_sessions WHERE expires_at <= ?;

-- name: GetSetting :one
SELECT * FROM operator_settings WHERE key = ? LIMIT 1;

-- name: UpsertSetting :one
INSERT INTO operator_settings (key, value, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ? LIMIT 1;

-- name: UpsertRecoveryVault :one
INSERT INTO recovery_vaults (
    user_id,
    user_pubkey,
    version,
    kdf_alg,
    kdf_params_json,
    salt_b64,
    nonce_b64,
    ciphertext_b64,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET
    user_pubkey = excluded.user_pubkey,
    version = excluded.version,
    kdf_alg = excluded.kdf_alg,
    kdf_params_json = excluded.kdf_params_json,
    salt_b64 = excluded.salt_b64,
    nonce_b64 = excluded.nonce_b64,
    ciphertext_b64 = excluded.ciphertext_b64,
    updated_at = excluded.updated_at
RETURNING *;

-- name: GetRecoveryVaultByUserID :one
SELECT * FROM recovery_vaults WHERE user_id = ? LIMIT 1;

-- name: DeleteRecoveryVaultByUserID :exec
DELETE FROM recovery_vaults WHERE user_id = ?;

-- name: CreatePairingRequest :one
INSERT INTO pairing_requests (
    id,
    oauth_state,
    user_id,
    target_user_pubkey,
    github_login,
    node_name,
    os_name,
    node_pubkey_b64,
    eph_x25519_pub_b64,
    status,
    approver_node_id,
    approver_eph_x25519_pub_b64,
    approver_signature_b64,
    handoff_nonce_b64,
    encrypted_handoff_b64,
    error_msg,
    expires_at,
    created_at
) VALUES (?, ?, NULL, '', '', ?, ?, ?, ?, ?, '', '', '', '', '', '', ?, ?)
RETURNING *;

-- name: GetPairingRequestByState :one
SELECT * FROM pairing_requests WHERE oauth_state = ? LIMIT 1;

-- name: GetPairingRequestByID :one
SELECT * FROM pairing_requests WHERE id = ? LIMIT 1;

-- name: BindPairingRequestToUser :one
UPDATE pairing_requests
SET user_id = ?, target_user_pubkey = ?, github_login = ?, status = 'awaiting_peer', expires_at = ?
WHERE oauth_state = ?
RETURNING *;

-- name: ListPendingPairingRequestsByPubkey :many
SELECT * FROM pairing_requests
WHERE target_user_pubkey = ? AND status = 'awaiting_peer' AND expires_at > ?
ORDER BY created_at ASC;

-- name: ApprovePairingRequest :one
UPDATE pairing_requests
SET status = 'approved',
    approver_node_id = ?,
    approver_eph_x25519_pub_b64 = ?,
    approver_signature_b64 = ?,
    handoff_nonce_b64 = ?,
    encrypted_handoff_b64 = ?
WHERE id = ? AND target_user_pubkey = ? AND status = 'awaiting_peer'
RETURNING *;

-- name: SetPairingRequestTerminalStatus :one
UPDATE pairing_requests
SET status = ?, error_msg = ?
WHERE id = ? AND status = 'awaiting_peer'
RETURNING *;

-- name: DeleteExpiredPairingRequests :exec
DELETE FROM pairing_requests WHERE expires_at <= ?;
