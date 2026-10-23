CREATE TABLE nodes (
  name       TEXT PRIMARY KEY,
  address    TEXT NOT NULL UNIQUE,
  pin        TEXT NOT NULL,
  not_after  INTEGER NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
