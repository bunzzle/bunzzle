CREATE TABLE suppressions_v22 (
  project_id        TEXT NOT NULL,
  address           TEXT NOT NULL,
  scope             TEXT NOT NULL CHECK (scope IN ('all', 'bulk')),
  reason            TEXT NOT NULL,
  detail            TEXT,
  source_message_id TEXT,
  created_at        INTEGER NOT NULL,
  expires_at        INTEGER,
  PRIMARY KEY (project_id, address, scope)
) STRICT;

INSERT INTO suppressions_v22 (project_id, address, scope, reason, detail, source_message_id, created_at, expires_at)
SELECT project_id, address, scope, reason, detail, source_message_id, created_at, expires_at FROM suppressions;

DROP TABLE suppressions;
ALTER TABLE suppressions_v22 RENAME TO suppressions;

CREATE TABLE stats_daily_v22 (
  project_id TEXT NOT NULL,
  day        TEXT NOT NULL,
  domain     TEXT NOT NULL,
  tag        TEXT NOT NULL,
  metric     TEXT NOT NULL,
  n          INTEGER NOT NULL,
  PRIMARY KEY (project_id, day, domain, tag, metric)
) STRICT;

INSERT INTO stats_daily_v22 (project_id, day, domain, tag, metric, n)
SELECT project_id, day, domain, tag, metric, n FROM stats_daily;

DROP TABLE stats_daily;
ALTER TABLE stats_daily_v22 RENAME TO stats_daily;
