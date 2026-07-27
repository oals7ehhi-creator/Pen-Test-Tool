-- 0004 Budget charge-before-send ledger + durable intent (down). EXACT inverse of 0004_...up.sql.
--   * Drops the two tables 0004 created (CASCADE clears their triggers / RLS policies / FKs).
--   * Drops the three functions 0004 created (with explicit signatures).
--   * Does NOT touch pgcrypto, reject_mutation(), or any 0002/0003-owned object — those pre-date 0004.

DROP TABLE IF EXISTS budget_reservation CASCADE;
DROP TABLE IF EXISTS engagement_runtime_counter CASCADE;

DROP FUNCTION IF EXISTS budget_charge_and_intent(UUID, UUID, UUID, TEXT, TEXT, TEXT, INT);
DROP FUNCTION IF EXISTS audit_append(UUID, TEXT, UUID, TEXT, TEXT, TEXT, UUID, UUID, JSONB);
DROP FUNCTION IF EXISTS budget_reservation_transition();
