-- One row per shared secret. Everything here is either ciphertext or
-- metadata the server needs to enforce limits; no plaintext, no IPs.
CREATE TABLE secrets (
    id              TEXT    NOT NULL PRIMARY KEY,
    header          BLOB    NOT NULL,              -- public 36-byte envelope header
    meta            BLOB    NOT NULL,              -- encrypted metadata record
    chunk_count     INTEGER NOT NULL CHECK (chunk_count >= 1),
    chunk_size      INTEGER NOT NULL CHECK (chunk_size >= 1),
    owner_token     BLOB    NOT NULL,              -- SHA-256 of the deletion token
    state           TEXT    NOT NULL CHECK (state IN ('uploading', 'sealed', 'burned')),
    max_views       INTEGER NOT NULL CHECK (max_views >= 1),
    views           INTEGER NOT NULL DEFAULT 0 CHECK (views >= 0),
    expires_at      INTEGER NOT NULL,
    upload_deadline INTEGER NOT NULL,
    burned_at       INTEGER
) STRICT;

CREATE INDEX secrets_expires_at ON secrets (expires_at);
CREATE INDEX secrets_state ON secrets (state);
