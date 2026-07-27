-- =============================================================================================================
-- 0005  Budget claimed-lease sweeper  (Phase 2 slice 5b; Phase 0 doc 04 §8.1 sweeper rule)
-- -------------------------------------------------------------------------------------------------------------
-- The charge-before-send ledger (0004) leaves a 'claimed' lease behind if a broker crashes between claiming and
-- charging. Such a lease reserves capacity (it counts against availability = total - used - live-claimed) until its
-- deadline. The SWEEPER reclaims that capacity: it transitions ONLY 'claimed' leases past their `expires_at` to
-- 'expired'. It MUST NOT touch 'charged' (terminal, irreversible) or 'released' leases — the budget_reservation
-- transition trigger (0004) independently rejects any expire-after-charge or expire-before-deadline, so the sweeper
-- cannot violate the charge-before-send guarantee even if its predicate were wrong.
--
-- Extension-free; reuses the 0004 transition trigger. The down migration drops only this function.
-- =============================================================================================================

-- Expire every past-deadline 'claimed' lease (freeing its reserved capacity) and return how many were swept. Each
-- UPDATE fires budget_reservation_transition(), which re-checks (deadline passed, not charged) and stamps resolved_at.
CREATE FUNCTION sweep_expired_leases() RETURNS integer AS $$
DECLARE
  n integer;
BEGIN
  WITH swept AS (
    UPDATE budget_reservation
       SET state = 'expired'
     WHERE state = 'claimed' AND expires_at <= now()
    RETURNING 1
  )
  SELECT count(*) INTO n FROM swept;
  RETURN n;
END; $$ LANGUAGE plpgsql;
