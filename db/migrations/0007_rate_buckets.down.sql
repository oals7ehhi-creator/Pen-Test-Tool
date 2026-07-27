-- 0007 request-rate token buckets (down). EXACT inverse of 0007_...up.sql.
DROP TABLE IF EXISTS rate_bucket CASCADE;
DROP FUNCTION IF EXISTS take_rate_tokens(UUID, UUID, TEXT);
