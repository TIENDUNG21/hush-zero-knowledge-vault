-- Token buckets keyed by HMAC(server key, client network) and bucket name.
CREATE TABLE rate_buckets (
    bucket     TEXT NOT NULL PRIMARY KEY,
    tokens     REAL NOT NULL,
    updated_at REAL NOT NULL
) STRICT, WITHOUT ROWID;
