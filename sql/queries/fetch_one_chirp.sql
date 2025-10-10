-- name: FetchOneChirp :one
SELECT * FROM chirps WHERE id = $1;