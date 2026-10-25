ALTER TABLE projects ADD COLUMN new_recipients_auto INTEGER NOT NULL DEFAULT 0
  CHECK (new_recipients_auto IN (0, 1));

UPDATE projects SET new_recipients_auto = 1
 WHERE id = 'default' AND NOT EXISTS (SELECT 1 FROM api_keys) AND NOT EXISTS (SELECT 1 FROM messages);
