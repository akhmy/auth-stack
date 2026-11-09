-- name: CreateSession :exec
WITH new_session AS (
INSERT INTO sessions (user_id, expires_at)
VALUES (sqlc.arg(user_id), sqlc.arg(session_expires_at))
    RETURNING id
    )
INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
SELECT id, sqlc.arg(token_hash), sqlc.arg(token_expires_at)
FROM new_session;

-- name: ConsumeToken :exec
UPDATE refresh_tokens
SET consumed_at = now()
WHERE token_hash = $1;

-- name: GetSessionByTokenForUpdate :one
SELECT
    s.id,
    s.user_id,
    s.created_at,
    s.expires_at,
    s.revoked_at
FROM sessions s
JOIN refresh_tokens rt ON rt.session_id = s.id
WHERE rt.token_hash = $1
FOR UPDATE;

-- name: GetRefreshToken :one
SELECT
    id,
    session_id,
    token_hash,
    expires_at,
    consumed_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: RevokeSession :exec
UPDATE sessions
SET revoked_at = now()
WHERE id = $1;

-- name: RevokeSessionByToken :execrows
UPDATE sessions s
SET revoked_at = now()
FROM refresh_tokens rt
WHERE rt.session_id = s.id
    AND rt.token_hash = $1
    AND s.revoked_at IS NULL;
