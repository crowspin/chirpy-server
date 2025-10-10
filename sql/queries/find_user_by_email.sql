-- name: FetchUserByEmail :one
SELECT * FROM users WHERE email = $1;