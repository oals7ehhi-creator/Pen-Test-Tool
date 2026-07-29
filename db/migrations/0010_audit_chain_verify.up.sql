-- =============================================================================================================
-- 0010  Audit-chain VERIFICATION: prove the hash chain is intact  (Phase 2 slice 5i; Phase 0 doc 04 §9)
-- -------------------------------------------------------------------------------------------------------------
-- `audit_append` (0004) makes the audit log tamper-EVIDENT: every event binds the previous head, its position, the
-- chain, the event type and the payload digest into `event_hash`, and `audit_event` is append-only (0002 rejects
-- UPDATE/DELETE). But "evident" only means something if somebody can actually LOOK: evidence nobody checks detects
-- nothing. This migration adds the checker — the read-only counterpart that recomputes the chain end to end and says,
-- with a fixed reason, whether it is intact.
--
-- THREAT MODEL. The append-only triggers stop the application from rewriting history; they do NOT stop an actor with
-- direct database privileges (a compromised operator, a restored/edited backup, a malicious DBA) who can disable a
-- trigger or write the table directly. That actor is exactly who the hash chain exists to catch, and `verify_audit_chain`
-- is how they get caught. It re-derives every digest from the stored payload rather than trusting any stored digest.
--
-- WHAT IS CHECKED, in order, first failure wins (a deterministic reason, never a guess):
--   0. null_field           — a field bound into the chain is NULL. This check is LOAD-BEARING, not hygiene: in SQL
--                             `NULL <> x` evaluates to NULL, and `IF NULL THEN` does NOT fire, so a NULL operand would
--                             silently SKIP the very comparison meant to catch it. An actor who rewrites a payload and
--                             NULLs the digests that would expose it would otherwise be attested `ok`. Every
--                             comparison below is additionally written `IS DISTINCT FROM` so a NULL can never mean
--                             "no difference found" — but the explicit guard is what covers the case where BOTH sides
--                             are NULL (a NULL operand also makes the RECOMPUTED hash NULL).
--   1. identity_mismatch    — an event's tenant/engagement is not the CHAIN's. The chain is the authoritative identity
--                             (0002's audit_event_identity trigger enforces this on the write path this threat model
--                             presumes disabled), so it is re-derived here rather than trusted.
--   2. genesis_mismatch     — the first event's prev_hash is not the chain's genesis value (64 zeros).
--   3. seq_gap              — seq is not the contiguous 1..N (an event removed, or numbering forged).
--   4. chain_broken         — an event's prev_hash is not the previous event's event_hash (a link cut or a reorder).
--   5. payload_tampered     — payload_sha256 does not equal sha256 over the stored payload (the payload was edited).
--   6. event_hash_mismatch  — event_hash does not equal the recomputed chained pre-image (type/seq/chain/digest edited).
--   7. head_mismatch        — the chain head does not equal the last event. This is the TRUNCATION check and it is why
--                             the head is stored at all: lopping the last N events off leaves a perfectly valid chain
--                             PREFIX that checks 1-6 all pass. Only the head reveals that events used to follow.
--
-- INVOCATION: SECURITY INVOKER, so it verifies exactly what the caller can SEE. Under FORCE RLS a per-tenant broker
-- role verifies its own chains; a system auditor role (RLS-exempt) verifies across tenants. Note the fail-closed
-- consequence: if a caller can see only PART of a chain, verification reports a break rather than a pass — you cannot
-- attest to what you cannot read.
--
-- DURABILITY NOTE: the digests are taken over `payload::text`, the JSONB rendering (as `audit_append` does), so
-- verification is exact for a given Postgres. A future major version that changed JSONB text rendering would need the
-- chain re-attested — the usual trade-off for hashing a structured value, recorded here deliberately.
--
-- COVERAGE LIMIT — WHAT THE PRE-IMAGE DOES NOT BIND. `event_hash` covers prev_hash, seq, chain_id, event_type and
-- payload_sha256 (hence the payload). It does NOT cover occurred_at, actor_type/actor_id/actor_role,
-- subject_type/subject_id, or related_event_id. A direct-DB actor who rewrites WHO performed an event, WHEN it
-- occurred, WHAT it was about, or WHICH event it relates to leaves the chain intact and this function returns `ok`.
-- So `ok` attests to ORDER, TYPE and PAYLOAD — NOT to attribution, timing, or the intent↔completion binding. (The
-- chain's tenant/engagement identity IS re-derived here, check 1, because the chain itself carries it.) Widening the
-- pre-image is a BREAKING change — every existing chain would need re-attesting — so it belongs to a versioned
-- pre-image in a later migration, not a silent edit here.
--
-- LIMIT — AN ACTOR WHO CAN WRITE audit_chain CAN PRESENT ANY CHAIN. `audit_chain` is not itself append-only, so an
-- attacker who re-derives the hashes and updates the head can delete, INSERT, or rewrite history wholesale and this
-- function will return `ok`. The stored head does not bound that; it only costs one extra UPDATE. Detecting it
-- requires an EXTERNAL anchor — a witnessed/exported head (§9 external attestation), which is NOT yet implemented in
-- this repository. Until it is, `ok` means "internally consistent", not "not rewritten"; that gap is real and is
-- recorded here and in docs/phase-2 rather than implied away.
--
-- search_path is PINNED: the very actor this function exists to catch could otherwise create a shadowing `digest()`
-- (classically via pg_temp, which Postgres searches first) and have the verifier hash with the attacker's function.
--
-- Read-only: this function writes nothing, so verification can never itself alter the evidence. Extension-free
-- (pgcrypto's digest() is provisioned by 0002). The down migration drops only this function.
-- =============================================================================================================

CREATE FUNCTION verify_audit_chain(p_chain_id UUID)
RETURNS TABLE (ok BOOLEAN, events_checked BIGINT, bad_seq BIGINT, reason TEXT) AS $$
DECLARE
  ch             audit_chain%ROWTYPE;
  ev             audit_event%ROWTYPE;
  v_expect_prev  CHAR(64) := repeat('0', 64);   -- the genesis head_hash (0002 default)
  v_expect_seq   BIGINT := 0;
  v_payload_hash CHAR(64);
  v_event_hash   CHAR(64);
  v_checked      BIGINT := 0;
BEGIN
  SELECT * INTO ch FROM audit_chain WHERE id = p_chain_id;
  IF NOT FOUND THEN
    -- Unknown, or invisible under RLS — either way this caller cannot attest to it.
    RETURN QUERY SELECT false, 0::BIGINT, NULL::BIGINT, 'unknown_chain'::TEXT;
    RETURN;
  END IF;

  IF ch.head_seq IS NULL OR ch.head_hash IS NULL THEN
    RETURN QUERY SELECT false, 0::BIGINT, ch.head_seq, 'null_field'::TEXT;
    RETURN;
  END IF;

  FOR ev IN SELECT * FROM audit_event WHERE chain_id = p_chain_id ORDER BY seq LOOP
    -- CHECK 0 — every field the chain binds must be present. A NULL here would make both the stored value AND the
    -- recomputed hash NULL, so even `IS DISTINCT FROM` would find "no difference" and the tamper would be attested ok.
    IF ev.seq IS NULL OR ev.event_type IS NULL OR ev.payload IS NULL
       OR ev.payload_sha256 IS NULL OR ev.prev_hash IS NULL OR ev.event_hash IS NULL THEN
      RETURN QUERY SELECT false, v_checked, ev.seq, 'null_field'::TEXT;
      RETURN;
    END IF;

    v_expect_seq := v_expect_seq + 1;

    IF ev.seq IS DISTINCT FROM v_expect_seq THEN
      RETURN QUERY SELECT false, v_checked, ev.seq, 'seq_gap'::TEXT;
      RETURN;
    END IF;

    -- The CHAIN carries the authoritative tenant/engagement identity (0002's audit_event_identity trigger enforces it
    -- on the write path this threat model presumes disabled), so re-derive it rather than trust the row's own copy.
    -- IS DISTINCT FROM is required, not stylistic: both columns are legitimately NULL on tenant/global chains.
    IF ev.tenant_id IS DISTINCT FROM ch.tenant_id OR ev.engagement_id IS DISTINCT FROM ch.engagement_id THEN
      RETURN QUERY SELECT false, v_checked, ev.seq, 'identity_mismatch'::TEXT;
      RETURN;
    END IF;

    IF ev.prev_hash IS DISTINCT FROM v_expect_prev THEN
      RETURN QUERY SELECT false, v_checked, ev.seq,
        CASE WHEN v_expect_seq = 1 THEN 'genesis_mismatch' ELSE 'chain_broken' END::TEXT;
      RETURN;
    END IF;

    -- Re-derive BOTH digests from the stored payload; never trust a stored digest to vouch for itself.
    v_payload_hash := encode(digest(convert_to(ev.payload::text, 'utf8'), 'sha256'), 'hex');
    IF ev.payload_sha256 IS DISTINCT FROM v_payload_hash THEN
      RETURN QUERY SELECT false, v_checked, ev.seq, 'payload_tampered'::TEXT;
      RETURN;
    END IF;

    -- Exactly the pre-image audit_append (0004) binds: prev : seq : chain : type : payload digest — built from the
    -- values just VERIFIED (v_expect_prev, v_payload_hash), not from the stored copies, so the recomputation cannot be
    -- fed by the same bytes it is meant to check.
    v_event_hash := encode(digest(convert_to(
        v_expect_prev || ':' || ev.seq::text || ':' || p_chain_id::text || ':' || ev.event_type || ':' ||
        v_payload_hash, 'utf8'), 'sha256'), 'hex');
    IF ev.event_hash IS DISTINCT FROM v_event_hash THEN
      RETURN QUERY SELECT false, v_checked, ev.seq, 'event_hash_mismatch'::TEXT;
      RETURN;
    END IF;

    v_expect_prev := ev.event_hash;
    v_checked := v_checked + 1;
  END LOOP;

  -- TRUNCATION: checks 0-6 pass on any valid PREFIX, so only the stored head proves nothing was lopped off the end.
  IF ch.head_seq IS DISTINCT FROM v_expect_seq OR ch.head_hash IS DISTINCT FROM v_expect_prev THEN
    RETURN QUERY SELECT false, v_checked, ch.head_seq, 'head_mismatch'::TEXT;
    RETURN;
  END IF;

  RETURN QUERY SELECT true, v_checked, NULL::BIGINT, 'ok'::TEXT;
END; $$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public;
