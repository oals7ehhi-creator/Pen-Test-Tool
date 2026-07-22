-- 0001 init (up). Phase 1 baseline only. The full authorization/scope schema (Phase 0 doc 04) lands in Phase 2.
-- pgcrypto provides digest()/gen_random_uuid() used by later content-addressed/audit tables.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Minimal tenant baseline so isolation wiring has something to build on. Real columns/constraints arrive in Phase 2.
CREATE TABLE tenant (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
