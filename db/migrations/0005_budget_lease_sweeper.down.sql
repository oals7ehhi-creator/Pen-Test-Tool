-- 0005 budget claimed-lease sweeper (down). EXACT inverse of 0005_...up.sql — drops only the function it created.
DROP FUNCTION IF EXISTS sweep_expired_leases();
