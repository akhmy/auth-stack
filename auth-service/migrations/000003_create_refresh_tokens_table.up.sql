CREATE TABLE refresh_tokens (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id  BIGINT      NOT NULL REFERENCES sessions(id),
    token_hash  BYTEA       NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);