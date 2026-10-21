CREATE TABLE api_keys_v23 (
  id           TEXT PRIMARY KEY,
  project_id   TEXT,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  scope        TEXT NOT NULL CHECK (scope IN ('send', 'read', 'full', 'admin')),
  domains      TEXT,
  rate_limit   INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER,
  test         INTEGER NOT NULL DEFAULT 0,
  pool         TEXT,
  CHECK ((scope = 'admin') = (project_id IS NULL))
) STRICT;

INSERT INTO api_keys_v23 (id, project_id, name, token_hash, prefix, scope, domains, rate_limit,
  created_at, last_used_at, revoked_at, test, pool)
SELECT id, coalesce(project_id, 'default'), name, token_hash, prefix, scope, domains, rate_limit,
  created_at, last_used_at, revoked_at, test, pool FROM api_keys;

DROP TABLE api_keys;
ALTER TABLE api_keys_v23 RENAME TO api_keys;
CREATE INDEX api_keys_project ON api_keys (project_id);

CREATE TABLE admin_events (
  id          INTEGER PRIMARY KEY,
  kind        TEXT NOT NULL,
  project_id  TEXT NOT NULL,
  actor       TEXT NOT NULL,
  data        TEXT,
  occurred_at INTEGER NOT NULL
) STRICT;

CREATE INDEX admin_events_project ON admin_events (project_id, id);
