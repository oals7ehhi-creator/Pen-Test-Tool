-- 0001 init (down). Reverses 0001_init.up.sql exactly, restoring the prior (empty) schema.
DROP TABLE IF EXISTS tenant;
-- pgcrypto is left installed intentionally (extensions are shared infrastructure, not migration-owned state).
