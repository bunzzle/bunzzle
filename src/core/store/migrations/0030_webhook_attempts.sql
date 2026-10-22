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
