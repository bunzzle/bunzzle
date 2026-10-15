CREATE TABLE suppressions (
  address           TEXT NOT NULL,
  scope             TEXT NOT NULL CHECK (scope IN ('all', 'bulk')),
  reason            TEXT NOT NULL,
  detail            TEXT,
  source_message_id TEXT,
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER,
  PRIMARY KEY (address, scope)
) STRICT;

CREATE TABLE inbound (
  id          TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  message_id  TEXT,
  parsed      TEXT NOT NULL,
  epoch       INTEGER,
  wrapped     BLOB,
  raw         BLOB
) STRICT;

CREATE TABLE webhooks (
  id         TEXT PRIMARY KEY,
  url        TEXT NOT NULL,
  events     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  disabled_at INTEGER
) STRICT;

CREATE TABLE webhook_deliveries (
  id          TEXT PRIMARY KEY,
  webhook_id  TEXT NOT NULL REFERENCES webhooks (id),
  type        TEXT NOT NULL,
  payload     TEXT NOT NULL,
  attempt     INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL CHECK (state IN ('pending', 'sending', 'done', 'failed')),
  next_at     INTEGER NOT NULL,
  last_error  TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_at) WHERE state = 'pending';
