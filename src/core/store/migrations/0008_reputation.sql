CREATE TABLE warmup (
  ip          TEXT NOT NULL,
  provider    TEXT NOT NULL,
  started_day INTEGER NOT NULL,
  day         INTEGER NOT NULL,
  budget      INTEGER NOT NULL,
  sent        INTEGER NOT NULL DEFAULT 0,
  delivered   INTEGER NOT NULL DEFAULT 0,
  deferred    INTEGER NOT NULL DEFAULT 0,
  bounced     INTEGER NOT NULL DEFAULT 0,
  blocked     INTEGER NOT NULL DEFAULT 0,
  complained  INTEGER NOT NULL DEFAULT 0,
  state       TEXT NOT NULL CHECK (state IN ('warming', 'done')),
  history     TEXT NOT NULL DEFAULT '[]',
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (ip, provider)
) STRICT;

CREATE TABLE sender_stats (
  domain       TEXT NOT NULL,
  lane         TEXT NOT NULL,
  day          INTEGER NOT NULL,
  delivered    INTEGER NOT NULL DEFAULT 0,
  hard_bounced INTEGER NOT NULL DEFAULT 0,
  complained   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (domain, lane, day)
) STRICT;

CREATE TABLE key_stats (
  key_id TEXT NOT NULL,
  hour   INTEGER NOT NULL,
  bulk   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_id, hour)
) STRICT;

CREATE TABLE holds (
  id          TEXT PRIMARY KEY,
  target      TEXT NOT NULL,
  lane        TEXT NOT NULL,
  reason      TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  released_at INTEGER
) STRICT;

CREATE INDEX holds_active ON holds (target, lane) WHERE released_at IS NULL;
