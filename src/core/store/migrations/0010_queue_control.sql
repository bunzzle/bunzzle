CREATE TABLE suspensions (
  target     TEXT PRIMARY KEY,
  reason     TEXT NOT NULL,
  until      INTEGER,
  created_at INTEGER NOT NULL
) STRICT;
