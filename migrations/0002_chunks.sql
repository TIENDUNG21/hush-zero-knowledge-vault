-- Encrypted payload chunks (nonce || ciphertext || tag), uploaded one by one.
CREATE TABLE chunks (
    secret_id TEXT    NOT NULL REFERENCES secrets (id) ON DELETE CASCADE,
    idx       INTEGER NOT NULL CHECK (idx >= 0),
    data      BLOB    NOT NULL,
    UNIQUE (secret_id, idx)
) STRICT;
