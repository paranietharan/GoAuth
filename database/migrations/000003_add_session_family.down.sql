DROP INDEX IF EXISTS idx_sessions_family_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS family_id;
