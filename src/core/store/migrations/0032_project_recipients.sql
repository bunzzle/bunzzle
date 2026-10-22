ALTER TABLE projects ADD COLUMN new_recipients_per_day INTEGER;

CREATE TABLE project_recipients (
  project_id   TEXT NOT NULL,
  address_hash BLOB NOT NULL,
  last_at      INTEGER NOT NULL,
  PRIMARY KEY (project_id, address_hash)
) STRICT, WITHOUT ROWID;

CREATE INDEX project_recipients_last ON project_recipients (last_at);

CREATE TABLE project_usage_next (
  project_id TEXT NOT NULL,
  unit       TEXT NOT NULL CHECK (unit IN ('minute', 'hour', 'new_hour')),
  slot       INTEGER NOT NULL,
  n          INTEGER NOT NULL,
  PRIMARY KEY (project_id, unit, slot)
) STRICT, WITHOUT ROWID;

INSERT INTO project_usage_next SELECT project_id, unit, slot, n FROM project_usage;
DROP TABLE project_usage;
ALTER TABLE project_usage_next RENAME TO project_usage;

CREATE TABLE project_limit_notices_next (
  project_id  TEXT NOT NULL,
  span        TEXT NOT NULL
              CHECK (span IN ('hour', 'day', 'new', 'hour:reached', 'day:reached', 'new:reached')),
  notified_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, span)
) STRICT;

INSERT INTO project_limit_notices_next SELECT project_id, span, notified_at FROM project_limit_notices;
DROP TABLE project_limit_notices;
ALTER TABLE project_limit_notices_next RENAME TO project_limit_notices;
