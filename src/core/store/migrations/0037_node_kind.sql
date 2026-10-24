ALTER TABLE nodes ADD COLUMN kind TEXT NOT NULL DEFAULT 'delivery' CHECK (kind IN ('delivery', 'egress'));
