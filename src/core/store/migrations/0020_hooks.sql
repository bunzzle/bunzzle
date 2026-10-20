CREATE TABLE hooks (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  url        TEXT NOT NULL,
  timeout_ms INTEGER NOT NULL,
  on_error   TEXT NOT NULL,
  max_score  REAL,
  created_at INTEGER NOT NULL
);
