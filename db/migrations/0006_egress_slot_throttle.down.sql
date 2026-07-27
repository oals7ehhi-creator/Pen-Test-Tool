-- 0006 egress-slot throttle (down). EXACT inverse of 0006_...up.sql — drops only the two functions it created.
DROP FUNCTION IF EXISTS acquire_egress_slot(UUID, UUID, INT);
DROP FUNCTION IF EXISTS release_egress_slot(UUID, UUID, BOOLEAN, INT);
