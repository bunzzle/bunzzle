CREATE TABLE jobs_v3 (
  id          TEXT PRIMARY KEY,
  message_id  TEXT NOT NULL REFERENCES messages (id),
  target      TEXT NOT NULL DEFAULT '',
  state       TEXT NOT NULL CHECK (state IN ('ready', 'leased', 'unknown', 'done', 'dead')),
  priority    INTEGER NOT NULL DEFAULT 0,
  run_after   INTEGER NOT NULL,
  attempt     INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER,
  check_after INTEGER,
  expires_at  INTEGER,
  notices     INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT,
  updated_at  INTEGER NOT NULL,
  UNIQUE (message_id, target)
) STRICT;

INSERT INTO jobs_v3 (id, message_id, state, priority, run_after, attempt, lease_until,
                     check_after, last_error, updated_at)
SELECT message_id, message_id, state, priority, run_after, attempt, lease_until,
       check_after, last_error, updated_at
FROM jobs;

DROP TABLE jobs;
ALTER TABLE jobs_v3 RENAME TO jobs;

CREATE INDEX jobs_ready   ON jobs (priority, run_after) WHERE state = 'ready';
CREATE INDEX jobs_leased  ON jobs (lease_until)         WHERE state = 'leased';
CREATE INDEX jobs_unknown ON jobs (check_after)         WHERE state = 'unknown';

CREATE TABLE recipients (
  job_id     TEXT NOT NULL REFERENCES jobs (id),
  address    TEXT NOT NULL,
  status     TEXT NOT NULL
             CHECK (status IN ('queued', 'deferred', 'unknown', 'delivered', 'bounced', 'failed')),
  attempts   INTEGER NOT NULL DEFAULT 0,
  code       INTEGER,
  enhanced   TEXT,
  reply      TEXT,
  class      TEXT,
  scope      TEXT,
  suppress   INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (job_id, address)
) STRICT;

CREATE TABLE paths (
  source     TEXT NOT NULL,
  site       TEXT NOT NULL,
  state      TEXT NOT NULL CHECK (state IN ('open', 'slowed', 'paused')),
  until      INTEGER,
  reason     TEXT,
  pauses     INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (source, site)
) STRICT;
