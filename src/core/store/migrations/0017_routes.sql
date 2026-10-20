CREATE TABLE routes (
  id          TEXT PRIMARY KEY,
  address     TEXT NOT NULL,
  url         TEXT NOT NULL,
  format      TEXT NOT NULL CHECK (format IN ('parsed', 'raw')),
  created_at  INTEGER NOT NULL,
  disabled_at INTEGER
) STRICT;

CREATE UNIQUE INDEX routes_address ON routes (address) WHERE disabled_at IS NULL;

CREATE TABLE route_deliveries (
  id         TEXT PRIMARY KEY,
  route_id   TEXT NOT NULL REFERENCES routes (id),
  epoch      INTEGER,
  wrapped    BLOB,
  body       BLOB,
  size       INTEGER NOT NULL,
  attempt    INTEGER NOT NULL DEFAULT 0,
  state      TEXT NOT NULL CHECK (state IN ('pending', 'sending', 'done', 'failed')),
  next_at    INTEGER NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX route_deliveries_due ON route_deliveries (state, next_at);
