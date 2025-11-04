-- name: DeleteChirp :one
WITH deletedRows AS (
    DELETE FROM chirps AS c
    WHERE c.id = $1 AND c.user_id = $2 
    RETURNING *
) 
SELECT chirps.*, (SELECT COUNT(*) FROM deletedRows) AS deletedCt 
FROM chirps 
WHERE chirps.id = $1;