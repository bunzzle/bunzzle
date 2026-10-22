CREATE TABLE webhook_attempts (
  id          INTEGER PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES webhook_deliveries (id) ON DELETE CASCADE,
  at          INTEGER NOT NULL,
  status      INTEGER,
  error       TEXT,
  duration_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX webhook_attempts_delivery ON webhook_attempts (delivery_id, id);
CREATE INDEX webhook_deliveries_webhook ON webhook_deliveries (webhook_id, created_at);

CREATE TABLE webhook_resends (
  id          TEXT PRIMARY KEY,
  webhook_id  TEXT NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
  from_at     INTEGER NOT NULL,
  to_at       INTEGER NOT NULL,
  failed_only INTEGER NOT NULL CHECK (failed_only IN (0, 1)),
  cursor      TEXT,
  resent      INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL CHECK (state IN ('queued', 'done')),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX webhook_resends_queued ON webhook_resends (created_at) WHERE state = 'queued';
