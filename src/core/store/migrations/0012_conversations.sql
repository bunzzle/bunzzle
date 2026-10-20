CREATE TABLE conversations (
  message_id TEXT NOT NULL REFERENCES messages (id),
  attempt_at INTEGER NOT NULL,
  session    INTEGER NOT NULL,
  data       TEXT NOT NULL,
  PRIMARY KEY (message_id, attempt_at, session)
) STRICT;

CREATE INDEX conversations_age ON conversations (attempt_at);
