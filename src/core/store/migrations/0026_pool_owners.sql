CREATE TABLE pool_owners (
  pool       TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
