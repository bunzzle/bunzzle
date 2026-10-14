CREATE TABLE messages (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  payload    TEXT NOT NULL,
  metadata   TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE jobs (
  message_id  TEXT PRIMARY KEY REFERENCES messages (id),
  state       TEXT NOT NULL CHECK (state IN ('ready', 'leased', 'unknown', 'done', 'dead')),
  priority    INTEGER NOT NULL DEFAULT 0,
  run_after   INTEGER NOT NULL,
  attempt     INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER,
  check_after INTEGER,
  last_error  TEXT,
  updated_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX jobs_ready   ON jobs (priority, run_after) WHERE state = 'ready';
CREATE INDEX jobs_leased  ON jobs (lease_until)         WHERE state = 'leased';
CREATE INDEX jobs_unknown ON jobs (check_after)         WHERE state = 'unknown';

CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  message_id  TEXT NOT NULL REFERENCES messages (id),
  kind        TEXT NOT NULL,
  data        TEXT,
  source      TEXT NOT NULL,
  occurred_at INTEGER NOT NULL
) STRICT;

CREATE INDEX events_message ON events (message_id, id);
