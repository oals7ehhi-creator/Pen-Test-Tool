-- 0001 init (up). Phase 1 baseline only. The full authorization/scope schema (Phase 0 doc 04) lands in Phase 2.
-- No extensions are created here: gen_random_uuid() is in core PostgreSQL (>= 13). Any extension a later phase
-- needs (e.g. pgcrypto for digest()) is provisioned as a documented operator prerequisite by the migration that
-- first requires it, so every down migration stays an exact inverse of its up.

-- Minimal tenant baseline so isolation wiring has something to build on. Real columns/constraints arrive in Phase 2.
CREATE TABLE tenant (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
