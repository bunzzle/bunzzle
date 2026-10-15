CREATE TABLE domains (
  name       TEXT PRIMARY KEY,
  status     TEXT NOT NULL CHECK (status IN ('pending', 'verified')),
  records    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  checked_at INTEGER,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE api_keys (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  scope        TEXT NOT NULL CHECK (scope IN ('send', 'read', 'full')),
  domains      TEXT,
  rate_limit   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER
) STRICT;

CREATE TABLE idempotency (
  api_key_id TEXT NOT NULL,
  key        TEXT NOT NULL,
  body_hash  TEXT NOT NULL,
  message_id TEXT NOT NULL REFERENCES messages (id),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (api_key_id, key)
) STRICT;

CREATE INDEX idempotency_age ON idempotency (created_at);
