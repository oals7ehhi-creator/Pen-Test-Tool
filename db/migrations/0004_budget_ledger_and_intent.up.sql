-- =============================================================================================================
-- 0004  Budget charge-before-send ledger + durable intent  (Phase 2 slice 5a; Phase 0 doc 04 §8 / §8.1, §7.1 step 10)
-- -------------------------------------------------------------------------------------------------------------
-- Migration 0002 deliberately DEFERRED the runtime counters and the budget_reservation ledger to Phase 2 slice 5
-- (interlocks). This migration lands the FIRST interlock: the CONSERVATIVE charge-before-send budget ledger and the
-- durable "request.intent" audit event, so that the Guarded Egress Broker can never send a byte without the budget
-- already IRREVERSIBLY charged and a prior durable record committed (SI-017, SI-055, SI-062).
--
-- It creates:
--   * engagement_runtime_counter — the authoritative per-engagement monotonic `fence_seq` + rate/concurrency/circuit
--     runtime fields (§8). Only `fence_seq` is exercised by this slice; the other fields carry later interlocks.
--   * budget_reservation — the identifiable charge-before-send LEASE ledger (§8.1) with its full CHECK shape.
--   * budget_reservation_transition() — the explicit state-transition trigger that CARRIES the charge-before-send
--     guarantee (terminal 'charged'/'released'/'expired'; owner+fence-token gating; the ONE `request_budget_used`
--     increment; no release/expire after charge; live-claim theft rejected). Behavioural, not prose (§8.1).
--   * audit_append() — the atomic hash-chained append primitive (locks the chain head, derives seq/prev_hash and the
--     trigger-computed payload/event hashes, advances the head) that the intent commit uses and later audit wiring
--     (slice 5d) reuses. The operator cannot forge seq/prev_hash/event_hash — they are DERIVED here.
--   * budget_charge_and_intent() — the §7.1-step-10 procedure as ONE atomic function: lock the runtime counter,
--     re-check e-stop, verify availability > 0, allocate the fence token, write the 'claimed' lease, transition it to
--     'charged' (used += 1), and append the durable 'request.intent' event — all in the caller's transaction, BEFORE
--     any DNS/TCP/TLS. Any denial/failure RAISEs and rolls the whole thing back (fail-closed; nothing was sent).
--
-- Extension-free (pgcrypto's digest() is already provisioned by 0002); reject_mutation() is owned by 0002 and reused.
-- The down migration is an EXACT inverse (drops only what this migration creates), verified by `migrate:ci`.
-- =============================================================================================================

-- -------------------------------------------------------------------------------------------------------------
-- engagement_runtime_counter (§8): one row per engagement; the authoritative monotonic fence source.
-- -------------------------------------------------------------------------------------------------------------
CREATE TABLE engagement_runtime_counter (
  engagement_id      UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  window_started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  requests_in_window INT NOT NULL DEFAULT 0 CHECK (requests_in_window >= 0),
  in_flight          INT NOT NULL DEFAULT 0 CHECK (in_flight >= 0),      -- HTTP requests currently on the wire
  ws_in_flight       INT NOT NULL DEFAULT 0 CHECK (ws_in_flight >= 0),   -- established ws/wss connections
  fence_seq          BIGINT NOT NULL DEFAULT 0 CHECK (fence_seq >= 0),   -- AUTHORITATIVE monotonic fence source
  last_request_at    TIMESTAMPTZ,
  circuit_state      TEXT NOT NULL DEFAULT 'closed' CHECK (circuit_state IN ('closed','open','half_open')),
  circuit_opened_at  TIMESTAMPTZ,
  consecutive_errors INT NOT NULL DEFAULT 0 CHECK (consecutive_errors >= 0),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);

-- -------------------------------------------------------------------------------------------------------------
-- budget_reservation (§8.1): the CONSERVATIVE charge-before-send lease (no sent-but-uncharged traffic).
-- -------------------------------------------------------------------------------------------------------------
CREATE TABLE budget_reservation (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  spec_id        UUID NOT NULL,
  grant_jti      TEXT NOT NULL,                    -- ties the lease to exactly one single-use grant
  state          TEXT NOT NULL DEFAULT 'claimed'
                 CHECK (state IN ('claimed','charged','released','expired')),
  owner          TEXT NOT NULL,                    -- the broker instance holding this LEASE
  fence_token    BIGINT NOT NULL,                  -- from engagement_runtime_counter.fence_seq (authoritative)
  claimed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  charged_at     TIMESTAMPTZ,                      -- set when claimed->charged (WITH the intent commit, BEFORE send)
  expires_at     TIMESTAMPTZ NOT NULL,             -- CLAIM deadline; renewable while 'claimed'
  resolved_at    TIMESTAMPTZ,                      -- when released/expired
  UNIQUE (id, tenant_id),
  UNIQUE (tenant_id, grant_jti),                   -- one lease per grant (also blocks JTI reuse across leases)
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (spec_id, tenant_id, engagement_id) REFERENCES request_spec(id, tenant_id, engagement_id),
  CONSTRAINT charged_has_time        CHECK (state <> 'charged' OR charged_at IS NOT NULL),
  CONSTRAINT no_release_after_charge CHECK (NOT (state='released' AND charged_at IS NOT NULL)),
  CONSTRAINT no_expire_after_charge  CHECK (NOT (state='expired'  AND charged_at IS NOT NULL))
);

-- Explicit state-transition trigger (behavioural enforcement, not prose). Rejects every illegal transition, the
-- clearing/altering of charged_at, release/expiry after charge, non-owner or stale-fence transitions, and any second
-- increment of request_budget_used. Terminal states are immutable. This trigger carries the charge-before-send guarantee.
CREATE FUNCTION budget_reservation_transition() RETURNS trigger AS $$
BEGIN
  -- (0) Terminal states are immutable: charged / released / expired can never be transitioned again.
  IF OLD.state IN ('charged','released','expired') THEN
    RAISE EXCEPTION 'budget lease % is terminal (state=%): no further transition', OLD.id, OLD.state;
  END IF;
  -- OLD.state is now 'claimed'. (1) Immutable identity/anchor columns may never change on any transition.
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.engagement_id <> OLD.engagement_id
     OR NEW.spec_id <> OLD.spec_id OR NEW.grant_jti <> OLD.grant_jti OR NEW.claimed_at <> OLD.claimed_at THEN
    RAISE EXCEPTION 'immutable budget-lease identity column changed';
  END IF;
  -- (2) charged_at is write-once: NULL while 'claimed'; set ONLY by the charge transition; never cleared/altered.
  IF OLD.charged_at IS NOT NULL THEN
    RAISE EXCEPTION 'charged_at already set on a claimed lease (invariant violation)';
  END IF;

  IF NEW.state = 'claimed' THEN
    -- RENEW (same owner: fence_token unchanged, only expires_at may extend) OR fenced takeover (new owner AFTER
    -- expiry, strictly advancing fence_token to fence off the stale owner). A live claim can never be stolen.
    IF NEW.owner = OLD.owner THEN
      IF NEW.fence_token <> OLD.fence_token THEN RAISE EXCEPTION 'renew must not change fence_token'; END IF;
    ELSE
      IF OLD.expires_at > now()             THEN RAISE EXCEPTION 'cannot take over a live claim before its deadline'; END IF;
      IF NEW.fence_token <= OLD.fence_token THEN RAISE EXCEPTION 'takeover must strictly advance fence_token'; END IF;
    END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'a claimed lease has no charged_at'; END IF;
    RETURN NEW;

  ELSIF NEW.state = 'charged' THEN
    -- (3) CHARGE: only the current owner presenting the CURRENT fence_token; sets charged_at; increments used ONCE.
    IF NEW.owner <> OLD.owner OR NEW.fence_token <> OLD.fence_token THEN
      RAISE EXCEPTION 'charge requires the current owner AND the current fence_token (stale/incorrect fence rejected)';
    END IF;
    IF NEW.charged_at IS NULL THEN RAISE EXCEPTION 'charge must set charged_at (write-once)'; END IF;
    -- The ONE increment of request_budget_used, bound to this single claimed->charged transition. Because 'charged'
    -- is terminal, this fires exactly once per lease => used cannot be double-incremented.
    UPDATE engagement SET request_budget_used = request_budget_used + 1
      WHERE id = NEW.engagement_id AND tenant_id = NEW.tenant_id;
    RETURN NEW;

  ELSIF NEW.state = 'released' THEN
    IF NEW.owner <> OLD.owner OR NEW.fence_token <> OLD.fence_token THEN
      RAISE EXCEPTION 'release requires the current owner AND fence_token';
    END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'cannot release after charge'; END IF;
    NEW.resolved_at := now();
    RETURN NEW;

  ELSIF NEW.state = 'expired' THEN
    -- SWEEPER: only a claim past its deadline may expire; never after charge. (Owner-agnostic: the sweeper is system.)
    IF OLD.expires_at > now()     THEN RAISE EXCEPTION 'cannot expire a claim before its deadline'; END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'cannot expire after charge'; END IF;
    NEW.resolved_at := now();
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'unknown target budget-lease state %', NEW.state;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER budget_reservation_transition_t
  BEFORE UPDATE ON budget_reservation
  FOR EACH ROW EXECUTE FUNCTION budget_reservation_transition();
-- Born shape: a lease MUST be born 'claimed' with charged_at / resolved_at NULL. A CHECK cannot enforce this (it also
-- runs on the charge UPDATE and would reject the legitimate claimed->charged transition), and the born-shape CHECKs
-- alone do NOT bound it (charged_has_time permits a directly-inserted 'charged' row). This BEFORE INSERT guard makes
-- budget_reservation_transition_t the ONLY route out of 'claimed', so the sole request_budget_used increment can never
-- be bypassed by inserting a lease already in a terminal state.
CREATE FUNCTION budget_reservation_insert_shape() RETURNS trigger AS $$
BEGIN
  IF NEW.state <> 'claimed' OR NEW.charged_at IS NOT NULL OR NEW.resolved_at IS NOT NULL THEN
    RAISE EXCEPTION 'a budget lease must be born claimed (state=claimed, charged_at/resolved_at NULL)';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER budget_reservation_insert_shape_t
  BEFORE INSERT ON budget_reservation
  FOR EACH ROW EXECUTE FUNCTION budget_reservation_insert_shape();
-- DELETE is revoked (a lease is never removed; terminal states are the audit record).
CREATE TRIGGER budget_reservation_no_delete_t
  BEFORE DELETE ON budget_reservation
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- -------------------------------------------------------------------------------------------------------------
-- audit_append(): atomic hash-chained append (§9). Locks the chain head, derives seq = head_seq + 1 and
-- prev_hash = head_hash, computes payload_sha256 over canonical(payload) and event_hash over the chained pre-image,
-- inserts the event with the chain's authoritative tenant/engagement identity, and advances the chain head. The
-- operator can neither choose seq/prev_hash/event_hash nor fork the chain; the returned id is the new event.
-- -------------------------------------------------------------------------------------------------------------
CREATE FUNCTION audit_append(
  p_chain_id         UUID,
  p_actor_type       TEXT,
  p_actor_id         UUID,
  p_actor_role       TEXT,
  p_event_type       TEXT,
  p_subject_type     TEXT,
  p_subject_id       UUID,
  p_related_event_id UUID,
  p_payload          JSONB
) RETURNS UUID AS $$
DECLARE
  ch             audit_chain%ROWTYPE;
  v_seq          BIGINT;
  v_prev         CHAR(64);
  v_payload_hash CHAR(64);
  v_event_hash   CHAR(64);
  v_id           UUID;
BEGIN
  -- Lock the chain head so concurrent appends serialize and seq/prev_hash cannot race.
  SELECT * INTO ch FROM audit_chain WHERE id = p_chain_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit_append: unknown chain %', p_chain_id;
  END IF;

  v_seq  := ch.head_seq + 1;
  v_prev := ch.head_hash;
  v_payload_hash := encode(digest(convert_to(p_payload::text, 'utf8'), 'sha256'), 'hex');
  -- event_hash binds the previous head, the position, the chain, the type and the payload digest → tamper-evident.
  v_event_hash := encode(digest(convert_to(
      v_prev || ':' || v_seq::text || ':' || p_chain_id::text || ':' || p_event_type || ':' || v_payload_hash,
      'utf8'), 'sha256'), 'hex');

  INSERT INTO audit_event (
    chain_id, tenant_id, engagement_id, seq, actor_type, actor_id, actor_role,
    event_type, subject_type, subject_id, related_event_id, payload, payload_sha256, prev_hash, event_hash
  ) VALUES (
    p_chain_id, ch.tenant_id, ch.engagement_id, v_seq, p_actor_type, p_actor_id, p_actor_role,
    p_event_type, p_subject_type, p_subject_id, p_related_event_id, p_payload, v_payload_hash, v_prev, v_event_hash
  ) RETURNING id INTO v_id;

  UPDATE audit_chain SET head_seq = v_seq, head_hash = v_event_hash WHERE id = p_chain_id;
  RETURN v_id;
END; $$ LANGUAGE plpgsql;

-- -------------------------------------------------------------------------------------------------------------
-- budget_charge_and_intent(): the §7.1 Stage-2 step-10 procedure as ONE atomic function, BEFORE any egress.
-- Returns the reservation id, the allocated fence token, and the durable intent event id on success; RAISEs (rolling
-- the whole transaction back — nothing was sent) on e-stop, exhaustion, or any invariant failure. Fail-closed.
-- -------------------------------------------------------------------------------------------------------------
CREATE FUNCTION budget_charge_and_intent(
  p_tenant           UUID,
  p_engagement       UUID,
  p_spec_id          UUID,
  p_grant_jti        TEXT,
  p_owner            TEXT,
  p_canonical_target TEXT,
  p_lease_ttl_s      INT
) RETURNS TABLE (reservation_id UUID, fence_token BIGINT, intent_event_id UUID) AS $$
DECLARE
  v_estop       BOOLEAN;
  v_total       INT;
  v_used        INT;
  v_claimed     INT;
  v_fence       BIGINT;
  v_ftoken      BIGINT;
  v_res         UUID;
  v_chain_id    UUID;
  v_spec_sha    CHAR(64);
  v_intent      UUID;
BEGIN
  IF p_lease_ttl_s IS NULL OR p_lease_ttl_s <= 0 THEN
    RAISE EXCEPTION 'invalid_lease_ttl';
  END IF;

  -- Ensure the runtime counter row exists, then take the per-engagement FOR UPDATE lock (serialises charges so the
  -- availability check and the charge cannot race).
  INSERT INTO engagement_runtime_counter (engagement_id, tenant_id, window_started_at)
    VALUES (p_engagement, p_tenant, now())
    ON CONFLICT (engagement_id) DO NOTHING;
  SELECT fence_seq INTO v_fence FROM engagement_runtime_counter
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  -- Re-check e-stop and read the budget UNDER the lock (fail-closed hard gate, SI-046).
  SELECT emergency_stop, request_budget_total, request_budget_used
    INTO v_estop, v_total, v_used
    FROM engagement WHERE id = p_engagement AND tenant_id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;
  IF v_estop THEN
    RAISE EXCEPTION 'emergency_stop';
  END IF;

  -- availability = total - used - count(live 'claimed' leases). Must be > 0 to charge.
  SELECT count(*) INTO v_claimed FROM budget_reservation
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant
      AND state = 'claimed' AND expires_at > now();
  IF (v_total - v_used - v_claimed) <= 0 THEN
    RAISE EXCEPTION 'budget_exhausted';
  END IF;

  -- Resolve the spec digest (for the intent payload) BEFORE the lease INSERT, so an unknown spec fails with the fixed
  -- reason `unknown_spec` rather than a raw foreign_key_violation from the lease's composite spec FK.
  SELECT spec_sha256 INTO v_spec_sha FROM request_spec
    WHERE id = p_spec_id AND tenant_id = p_tenant AND engagement_id = p_engagement;
  IF v_spec_sha IS NULL THEN
    RAISE EXCEPTION 'unknown_spec';
  END IF;

  -- Allocate the fence token (monotonic) under the same lock.
  v_ftoken := v_fence + 1;
  UPDATE engagement_runtime_counter SET fence_seq = v_ftoken WHERE engagement_id = p_engagement;

  -- Write the 'claimed' lease, then transition it to 'charged' (fires the trigger: used += 1, irreversible).
  v_res := gen_random_uuid();
  INSERT INTO budget_reservation (id, tenant_id, engagement_id, spec_id, grant_jti, state, owner, fence_token, expires_at)
    VALUES (v_res, p_tenant, p_engagement, p_spec_id, p_grant_jti, 'claimed', p_owner, v_ftoken,
            now() + make_interval(secs => p_lease_ttl_s));
  UPDATE budget_reservation SET state = 'charged', charged_at = now()
    WHERE budget_reservation.id = v_res AND budget_reservation.owner = p_owner
      AND budget_reservation.fence_token = v_ftoken AND budget_reservation.state = 'claimed';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'charge_failed';
  END IF;

  -- Resolve (get-or-create, serialised by the runtime lock above) the engagement audit chain, then append the
  -- durable 'request.intent' in the SAME transaction as the charge — nothing is contacted without this record.
  SELECT id INTO v_chain_id FROM audit_chain WHERE chain_key = 'engagement:' || p_engagement::text;
  IF v_chain_id IS NULL THEN
    INSERT INTO audit_chain (id, stream, tenant_id, engagement_id)
      VALUES (gen_random_uuid(), 'engagement', p_tenant, p_engagement) RETURNING id INTO v_chain_id;
  END IF;

  v_intent := audit_append(
    v_chain_id, 'broker', NULL, NULL, 'request.intent', 'request_spec', p_spec_id, NULL,
    jsonb_build_object(
      'spec_sha256', v_spec_sha,
      'grant_jti', p_grant_jti,
      'reservation_id', v_res,
      'canonical_target', p_canonical_target
    )
  );

  reservation_id := v_res; fence_token := v_ftoken; intent_event_id := v_intent;
  RETURN NEXT;
END; $$ LANGUAGE plpgsql;

-- -------------------------------------------------------------------------------------------------------------
-- Row-Level Security (doc 03): every tenant-scoped table isolates on app.tenant_id and fails closed when unset.
-- -------------------------------------------------------------------------------------------------------------
ALTER TABLE engagement_runtime_counter ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagement_runtime_counter FORCE  ROW LEVEL SECURITY;
ALTER TABLE budget_reservation         ENABLE ROW LEVEL SECURITY;
ALTER TABLE budget_reservation         FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON engagement_runtime_counter
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON budget_reservation
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
