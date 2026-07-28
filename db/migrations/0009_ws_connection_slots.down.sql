-- 0009 WebSocket connection admission slots (down). EXACT inverse of 0009_...up.sql — drops the table (with its indexes
-- + RLS policy, via CASCADE) and all three functions it created.
DROP TABLE IF EXISTS ws_slot CASCADE;
DROP FUNCTION IF EXISTS acquire_ws_slot(UUID, UUID, TEXT, UUID);
DROP FUNCTION IF EXISTS release_ws_slot(UUID, UUID, UUID);
DROP FUNCTION IF EXISTS sweep_expired_ws_slots();
