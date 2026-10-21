CREATE TABLE projects (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  per_hour     INTEGER,
  per_day      INTEGER,
  pool         TEXT,
  created_at   INTEGER NOT NULL,
  suspended_at INTEGER,
  deleted_at   INTEGER
) STRICT;

INSERT INTO projects (id, name, created_at) VALUES ('default', 'default', CAST(strftime('%s', 'now') AS INTEGER) * 1000);

ALTER TABLE api_keys ADD COLUMN project_id TEXT DEFAULT 'default';
ALTER TABLE domains ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE messages ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE jobs ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE email_index ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE stats_daily ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE webhooks ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE routes ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE templates ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE suppressions ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default';

DROP INDEX templates_name;
CREATE UNIQUE INDEX templates_name ON templates (project_id, name) WHERE deleted_at IS NULL;

CREATE INDEX api_keys_project ON api_keys (project_id);
CREATE INDEX domains_project ON domains (project_id);
CREATE INDEX email_index_project ON email_index (project_id, message_id);
CREATE INDEX webhooks_project ON webhooks (project_id);
CREATE INDEX routes_project ON routes (project_id);
