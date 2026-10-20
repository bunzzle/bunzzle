CREATE TABLE postmaster_stats (
  domain     TEXT NOT NULL,
  day        TEXT NOT NULL,
  spam_ratio REAL,
  reputation TEXT,
  data       TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  PRIMARY KEY (domain, day)
) STRICT;
