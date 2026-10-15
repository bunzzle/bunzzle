ALTER TABLE jobs ADD COLUMN path TEXT;

DROP TABLE paths;

CREATE TABLE paths (
  key        TEXT PRIMARY KEY,
  state      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;
