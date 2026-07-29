-- 0010 audit-chain verification (down). EXACT inverse of 0010_...up.sql — drops only the function it created.
DROP FUNCTION IF EXISTS verify_audit_chain(UUID);
