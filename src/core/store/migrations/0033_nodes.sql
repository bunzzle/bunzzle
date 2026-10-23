CREATE TABLE nodes (
  name        TEXT PRIMARY KEY,
  address     TEXT NOT NULL UNIQUE,
  pin         TEXT NOT NULL,
  not_after   INTEGER NOT NULL,
  ca          TEXT NOT NULL,
  trusted_cas TEXT NOT NULL,
  created_at  INTEGER NOT NULL
) STRICT;
