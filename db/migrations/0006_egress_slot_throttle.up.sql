-- =============================================================================================================
-- 0006  Egress-slot throttle: concurrency + min-spacing + circuit breaker  (Phase 2 slice 5c; Phase 0 doc 04 §8)
-- -------------------------------------------------------------------------------------------------------------
-- The pre-egress interlock that bounds a request against the engagement's runtime posture, atomically over the
-- engagement_runtime_counter (0004) under its FOR UPDATE lock, mirroring the pure `evaluateAcquire` / `recordResult`
-- logic in @pentest/broker (throttle.ts):
--   * acquire_egress_slot — CIRCUIT (an 'open' breaker within its cooldown denies; once elapsed one 'half_open' probe
--     is let through) → CONCURRENCY (in_flight >= max_concurrency denies) → SPACING (now - last_request_at <
--     min_request_interval_ms denies). Only a full allow RESERVES a slot (in_flight += 1, last_request_at = now).
--   * release_egress_slot — frees the slot (in_flight -= 1, floored at 0) and feeds the result to the breaker: a
--     success closes it; a failed 'half_open' probe re-opens; a 'closed' breaker opens once consecutive_errors reaches
--     the threshold.
-- Denials RAISE a fixed reason and change nothing (fail-closed; the caller queues/retries). Per-ENGAGEMENT only;
-- per-host concurrency + RPS token buckets land in a later slice. Extension-free. The down migration drops both funcs.
--
-- INVOCATION: SECURITY INVOKER — the broker calls these with its tenant GUC set, so RLS scopes them to that tenant.
--
-- KNOWN LIMITATION (concurrency, not safety): `in_flight` is a bare counter, so a broker that crashes BETWEEN acquire
-- and release strands a slot — repeated crashes could wedge an engagement at `max_concurrency`. This never causes an
-- UNSAFE egress (a stranded slot only makes the semaphore stricter), so it is a liveness, not a safety, concern. The
-- crash-safe fix — modelling each slot as a self-expiring lease row (owner + expires_at) reclaimed by a sweeper, like
-- the budget_reservation ledger (0004) — is deferred to the per-host slice that reworks this counter into per-host state.
-- =============================================================================================================

-- Acquire an egress slot, or RAISE a fixed reason (circuit_open / concurrency_exceeded / min_interval). p_cooldown_s is
-- how long an 'open' breaker waits before a probe; the concurrency cap + spacing come from the engagement row.
CREATE FUNCTION acquire_egress_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_cooldown_ms INT
) RETURNS void AS $$
DECLARE
  v_in_flight   INT;
  v_last        TIMESTAMPTZ;
  v_circuit     TEXT;
  v_opened_at   TIMESTAMPTZ;
  v_max_conc    INT;
  v_min_ms      INT;
  v_to_half     BOOLEAN := false;
BEGIN
  -- Ensure the runtime row exists, then take the per-engagement lock (serialises acquire/release).
  INSERT INTO engagement_runtime_counter (engagement_id, tenant_id, window_started_at)
    VALUES (p_engagement, p_tenant, now())
    ON CONFLICT (engagement_id) DO NOTHING;
  SELECT in_flight, last_request_at, circuit_state, circuit_opened_at
    INTO v_in_flight, v_last, v_circuit, v_opened_at
    FROM engagement_runtime_counter
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  SELECT max_concurrency, min_request_interval_ms INTO v_max_conc, v_min_ms
    FROM engagement WHERE id = p_engagement AND tenant_id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  -- (1) CIRCUIT: an 'open' breaker still cooling denies; once the cooldown elapses, allow ONE probe (open -> half_open).
  -- A breaker already 'half_open' has a probe outstanding — deny until its release resolves it, so exactly one probe
  -- is ever in flight (not up to max_concurrency of them). Cooldown is in MILLISECONDS, mirroring the pure layer + the
  -- spacing check below.
  IF v_circuit = 'open' THEN
    IF now() - COALESCE(v_opened_at, now()) >= (p_cooldown_ms || ' milliseconds')::interval THEN
      v_to_half := true;
    ELSE
      RAISE EXCEPTION 'circuit_open';
    END IF;
  ELSIF v_circuit = 'half_open' THEN
    RAISE EXCEPTION 'circuit_open';
  END IF;

  -- (2) CONCURRENCY.
  IF v_in_flight >= v_max_conc THEN
    RAISE EXCEPTION 'concurrency_exceeded';
  END IF;

  -- (3) SPACING.
  IF v_last IS NOT NULL AND now() - v_last < (v_min_ms || ' milliseconds')::interval THEN
    RAISE EXCEPTION 'min_interval';
  END IF;

  -- ALLOW: reserve the slot (and persist the open -> half_open probe transition if this acquire earned it).
  UPDATE engagement_runtime_counter
     SET in_flight = in_flight + 1,
         last_request_at = now(),
         circuit_state = CASE WHEN v_to_half THEN 'half_open' ELSE circuit_state END
   WHERE engagement_id = p_engagement AND tenant_id = p_tenant;
END; $$ LANGUAGE plpgsql;

-- Release an egress slot on completion: free the slot and transition the breaker on the request's success/failure.
CREATE FUNCTION release_egress_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_success    BOOLEAN,
  p_threshold  INT
) RETURNS void AS $$
DECLARE
  v_circuit   TEXT;
  v_errors    INT;
  v_new_state TEXT;
  v_new_err   INT;
  v_new_open  TIMESTAMPTZ;
BEGIN
  SELECT circuit_state, consecutive_errors INTO v_circuit, v_errors
    FROM engagement_runtime_counter
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  IF p_success THEN
    v_new_state := 'closed'; v_new_err := 0; v_new_open := NULL;
  ELSE
    v_new_err := v_errors + 1;
    IF v_circuit = 'half_open' THEN
      v_new_state := 'open'; v_new_open := now();
    ELSIF v_circuit = 'closed' AND v_new_err >= p_threshold THEN
      v_new_state := 'open'; v_new_open := now();
    ELSE
      -- stay where we are, accumulating the error run; keep the existing open timestamp.
      v_new_state := v_circuit;
      SELECT circuit_opened_at INTO v_new_open FROM engagement_runtime_counter
        WHERE engagement_id = p_engagement AND tenant_id = p_tenant;
    END IF;
  END IF;

  UPDATE engagement_runtime_counter
     SET in_flight = GREATEST(0, in_flight - 1),
         circuit_state = v_new_state,
         consecutive_errors = v_new_err,
         circuit_opened_at = v_new_open
   WHERE engagement_id = p_engagement AND tenant_id = p_tenant;
END; $$ LANGUAGE plpgsql;
