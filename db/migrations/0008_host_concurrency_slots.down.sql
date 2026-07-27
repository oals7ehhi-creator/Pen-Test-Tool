-- 0008 per-host concurrency slot leases (down). EXACT inverse of 0008_...up.sql — drops the table (with its indexes +
-- RLS policy, via CASCADE) and all three functions it created.
DROP TABLE IF EXISTS host_slot CASCADE;
DROP FUNCTION IF EXISTS acquire_host_slot(UUID, UUID, TEXT, TEXT, UUID, INT);
DROP FUNCTION IF EXISTS release_host_slot(UUID, UUID, UUID);
DROP FUNCTION IF EXISTS sweep_expired_slots();
