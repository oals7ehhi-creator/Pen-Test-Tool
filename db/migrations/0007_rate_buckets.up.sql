-- =============================================================================================================
-- 0007  Request-rate token buckets: global + per-host  (Phase 2 slice 5d; Phase 0 doc 04 §8)
-- -------------------------------------------------------------------------------------------------------------
-- The rate-limiting pre-egress interlock. Every request must draw a token from BOTH the engagement-GLOBAL bucket
-- (`global_max_rps`) and the PER-HOST bucket for its target host (`per_host_max_rps`); a bucket refills at its rate up
-- to a burst capacity. Draw is CHECK-BOTH-THEN-CONSUME-BOTH, atomically under the buckets' FOR UPDATE lock, mirroring
-- the pure evaluateRateLimit / refillAndTake logic in @pentest/broker (ratelimit.ts). A refusal RAISEs a fixed reason
-- and persists nothing (fail-closed; the caller queues/retries — "excess queued, not dropped").
--
-- One row per (engagement, scope): scope = 'global' for the engagement bucket, or the target host for a per-host
-- bucket. A fresh bucket is born FULL (tokens = capacity); capacity = GREATEST(1, rate) so a sub-1-rps rate can still
-- ever admit a request (one burst, then one per 1/rate seconds). SECURITY INVOKER — RLS scopes it to the broker's
-- tenant. Extension-free; the down migration drops the table + function.
--
-- SCOPE: request-rate only. Per-host CONCURRENCY (per_host_concurrency) is a separate per-host semaphore, deferred.
-- =============================================================================================================

CREATE TABLE rate_bucket (
  engagement_id UUID NOT NULL,
  tenant_id     UUID NOT NULL,
  scope         TEXT NOT NULL,               -- 'global' (engagement bucket) or the canonical target host
  tokens        DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
  refill_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (engagement_id, scope),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);

-- Draw one token from the engagement-global bucket AND the per-host bucket for p_host, or RAISE a fixed reason. The
-- rates come from the engagement; capacity = GREATEST(1, rate). Buckets are locked in a FIXED order (global first,
-- then host) so concurrent draws cannot deadlock. Tokens are persisted only on a full allow (a denial rolls back, so
-- no bucket loses accrued time and no token leaks from the bucket that WOULD have satisfied the request).
CREATE FUNCTION take_rate_tokens(
  p_tenant     UUID,
  p_engagement UUID,
  p_host       TEXT
) RETURNS void AS $$
DECLARE
  v_grate   DOUBLE PRECISION;
  v_hrate   DOUBLE PRECISION;
  v_gcap    DOUBLE PRECISION;
  v_hcap    DOUBLE PRECISION;
  v_gtok    DOUBLE PRECISION;
  v_htok    DOUBLE PRECISION;
  v_grefill TIMESTAMPTZ;
  v_hrefill TIMESTAMPTZ;
  v_gnew    DOUBLE PRECISION;
  v_hnew    DOUBLE PRECISION;
BEGIN
  IF p_host = 'global' THEN
    RAISE EXCEPTION 'invalid_host';  -- reserved scope key; a real host is never the literal 'global'
  END IF;

  SELECT global_max_rps, per_host_max_rps INTO v_grate, v_hrate
    FROM engagement WHERE id = p_engagement AND tenant_id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;
  v_gcap := GREATEST(1.0, v_grate);
  v_hcap := GREATEST(1.0, v_hrate);

  -- Get-or-create + lock BOTH buckets in a fixed order (global, then host). Fresh buckets are born full.
  INSERT INTO rate_bucket (engagement_id, tenant_id, scope, tokens)
    VALUES (p_engagement, p_tenant, 'global', v_gcap) ON CONFLICT (engagement_id, scope) DO NOTHING;
  INSERT INTO rate_bucket (engagement_id, tenant_id, scope, tokens)
    VALUES (p_engagement, p_tenant, p_host, v_hcap) ON CONFLICT (engagement_id, scope) DO NOTHING;
  SELECT tokens, refill_at INTO v_gtok, v_grefill
    FROM rate_bucket WHERE engagement_id = p_engagement AND scope = 'global' FOR UPDATE;
  SELECT tokens, refill_at INTO v_htok, v_hrefill
    FROM rate_bucket WHERE engagement_id = p_engagement AND scope = p_host FOR UPDATE;

  -- Refill each bucket by the elapsed time (floored at 0, capped at capacity), then require ≥ 1 token in BOTH before
  -- consuming. The GREATEST(0, …) floor mirrors the pure layer's Math.max(0, …): now() is the wall clock (not
  -- monotonic across transactions), so a backward step must never SUBTRACT tokens and starve a full bucket.
  v_gnew := LEAST(v_gcap, v_gtok + GREATEST(0, EXTRACT(EPOCH FROM (now() - v_grefill))) * v_grate);
  IF v_gnew < 1 THEN
    RAISE EXCEPTION 'rate_limited_global';
  END IF;
  v_hnew := LEAST(v_hcap, v_htok + GREATEST(0, EXTRACT(EPOCH FROM (now() - v_hrefill))) * v_hrate);
  IF v_hnew < 1 THEN
    RAISE EXCEPTION 'rate_limited_host';
  END IF;

  UPDATE rate_bucket SET tokens = v_gnew - 1, refill_at = now()
    WHERE engagement_id = p_engagement AND scope = 'global';
  UPDATE rate_bucket SET tokens = v_hnew - 1, refill_at = now()
    WHERE engagement_id = p_engagement AND scope = p_host;
END; $$ LANGUAGE plpgsql;

ALTER TABLE rate_bucket ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_bucket FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rate_bucket
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
