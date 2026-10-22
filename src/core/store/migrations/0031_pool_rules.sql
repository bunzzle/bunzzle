CREATE TABLE pool_rules (
  id         TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects (id),
  match      TEXT NOT NULL,
  target     TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX pool_rules_match ON pool_rules (coalesce(project_id, ''), match);
