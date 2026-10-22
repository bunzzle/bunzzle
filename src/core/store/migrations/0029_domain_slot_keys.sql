ALTER TABLE domains ADD COLUMN slot_keys INTEGER NOT NULL DEFAULT 0 CHECK (slot_keys IN (0, 1));
UPDATE domains SET slot_keys = 1 WHERE mode = 'delegated';
