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
