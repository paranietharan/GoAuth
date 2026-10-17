ALTER TABLE sessions ADD COLUMN IF NOT EXISTS family_id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE INDEX IF NOT EXISTS idx_sessions_family_id ON sessions (family_id);
