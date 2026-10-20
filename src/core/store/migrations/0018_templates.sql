CREATE TABLE templates (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  version    INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
) STRICT;

CREATE UNIQUE INDEX templates_name ON templates (name) WHERE deleted_at IS NULL;

CREATE TABLE template_versions (
  template_id TEXT NOT NULL REFERENCES templates (id),
  version     INTEGER NOT NULL,
  subject     TEXT NOT NULL,
  html        TEXT,
  text        TEXT,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (template_id, version)
) STRICT;
