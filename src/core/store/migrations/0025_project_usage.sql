CREATE TABLE project_usage (
  project_id TEXT NOT NULL,
  unit       TEXT NOT NULL CHECK (unit IN ('minute', 'hour')),
  slot       INTEGER NOT NULL,
  n          INTEGER NOT NULL,
  PRIMARY KEY (project_id, unit, slot)
) STRICT, WITHOUT ROWID;

CREATE TABLE project_limit_notices (
  project_id  TEXT NOT NULL,
  span        TEXT NOT NULL CHECK (span IN ('hour', 'day')),
  notified_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, span)
) STRICT;
