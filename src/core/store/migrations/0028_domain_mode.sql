ALTER TABLE domains ADD COLUMN mode TEXT NOT NULL DEFAULT 'records' CHECK (mode IN ('records', 'delegated'));
