CREATE TABLE email_index (
  message_id TEXT PRIMARY KEY REFERENCES messages (id),
  domain     TEXT NOT NULL,
  key_id     TEXT,
  test       INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX email_index_domain ON email_index (domain, message_id);

CREATE TABLE email_tags (
  message_id TEXT NOT NULL REFERENCES messages (id),
  tag        TEXT NOT NULL,
  PRIMARY KEY (tag, message_id)
) STRICT;

CREATE INDEX email_tags_message ON email_tags (message_id);

CREATE INDEX recipients_address ON recipients (address, job_id);

CREATE INDEX recipients_open ON recipients (status, job_id) WHERE status <> 'delivered';

CREATE TABLE stats_daily (
  day    TEXT NOT NULL,
  domain TEXT NOT NULL,
  tag    TEXT NOT NULL,
  metric TEXT NOT NULL,
  n      INTEGER NOT NULL,
  PRIMARY KEY (day, domain, tag, metric)
) STRICT;
