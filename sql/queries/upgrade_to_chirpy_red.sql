-- name: UpdateChirpyRedStatus :one
UPDATE users SET is_chirpy_red = $2 WHERE id = $1 RETURNING *;