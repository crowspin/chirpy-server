-- name: FetchRefreshToken :one
SELECT * FROM refresh_tokens WHERE token = $1 AND revoked_at == NULL AND expires_at > NOW();