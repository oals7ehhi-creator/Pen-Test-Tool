-- 0003 request_spec + secret-manager reference tables (down). Exact inverse of 0003_...up.sql.
--   * Drops the four tables 0003 created (CASCADE clears their triggers / RLS policies / FKs).
--   * Drops the two standalone functions 0003 created.
--   * Does NOT touch pgcrypto or reject_mutation() — those are owned by migration 0002 and existed before 0003.

DROP TABLE IF EXISTS request_spec CASCADE;
DROP TABLE IF EXISTS operator_query_value CASCADE;
DROP TABLE IF EXISTS operator_session CASCADE;
DROP TABLE IF EXISTS catalog_template CASCADE;

DROP FUNCTION IF EXISTS request_spec_derive_approval();
DROP FUNCTION IF EXISTS catalog_template_digest_verify();
