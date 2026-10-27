CREATE TABLE body_files (
  message_id TEXT PRIMARY KEY REFERENCES messages (id),
  epoch      INTEGER NOT NULL,
  size       INTEGER NOT NULL
) STRICT;

CREATE TABLE body_trash (
  message_id TEXT PRIMARY KEY,
  epoch      INTEGER NOT NULL
) STRICT;

CREATE TRIGGER body_files_trash AFTER DELETE ON body_files BEGIN
  INSERT OR REPLACE INTO body_trash (message_id, epoch) VALUES (old.message_id, old.epoch);
END;
