-- name: CreateUser :exec
INSERT INTO users(id, email, password_hash)
VALUES($1, $2, $3);

-- name: GetUserByEmail :one
SELECT id, email, password_hash
FROM users
WHERE email = $1;
