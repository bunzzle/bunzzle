CREATE TABLE bodies (
  message_id TEXT PRIMARY KEY REFERENCES messages (id),
  epoch      INTEGER NOT NULL,
  wrapped    BLOB NOT NULL,
  body       BLOB NOT NULL
) STRICT;

ALTER TABLE jobs ADD COLUMN unresolved_attempt INTEGER;
