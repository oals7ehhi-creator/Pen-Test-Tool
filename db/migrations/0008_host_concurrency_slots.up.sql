-- =============================================================================================================
-- 0008  Per-host concurrency: crash-safe egress-slot LEASES  (Phase 2 slice 5e; Phase 0 doc 04 §8)
-- -------------------------------------------------------------------------------------------------------------
-- The per-HOST concurrency interlock — the per-host version of the 5c semaphore, reworked as a CRASH-SAFE LEASE. Before
-- a request leaves, the broker must hold one live slot for its target host; the number of live slots per (engagement,
-- host) may never exceed `engagement.per_host_concurrency`. Unlike the per-ENGAGEMENT `in_flight` counter (0006, a bare
-- integer that a crashed broker strands), a per-host slot is a LEASE ROW with an `expires_at`: a slot only COUNTS while
-- it is unexpired, so a broker that crashes between acquire and release stops occupying its slot the instant the lease
-- expires — capacity self-heals WITHOUT the sweeper (exactly like the budget ledger's availability excluding
-- past-deadline claims, §8.1). The sweeper is table-size housekeeping, not a safety dependency.
--
-- This mirrors the pure `evaluateHostSlot` logic in @pentest/broker (hostconc.ts); the atomic count-under-lock + insert
-- lives here so the broker package stays I/O-free, exactly like the other interlocks. A refusal RAISEs a fixed reason
-- and persists nothing (fail-closed; the caller queues/retries).
--
-- ADMISSION SERIALISATION: count-then-insert must be atomic or two concurrent draws at cap-1 could both admit. We take
-- the per-engagement runtime-counter row FOR UPDATE (get-or-created, as 0006 does) as the serialisation point, so
-- host-slot admissions for one engagement are serialised (and serialise with the 0006 slot throttle on the SAME lock —
-- no over-admit, no cross-lock deadlock). A release is a bare DELETE (no lock): it only ever FREES a slot, so it can
-- never cause an over-admit against a concurrently-counting acquire.
--
-- SCOPE: per-host CONCURRENCY only. The per-ENGAGEMENT concurrency/spacing/circuit (0006) and the global/per-host RPS
-- token buckets (0007) are the sibling interlocks; the global `in_flight` counter's own crash-safe lease rework stays a
-- documented follow-up (a stranded global slot is a liveness, never a safety, concern — it only makes admission
-- STRICTER). SECURITY INVOKER — RLS scopes every function to the broker's tenant. Extension-free; the down migration
-- drops the table + all three functions.
-- =============================================================================================================

CREATE TABLE host_slot (
  id            UUID NOT NULL,                -- caller-supplied lease handle (broker: crypto.randomUUID), as budget_reservation
  engagement_id UUID NOT NULL,
  tenant_id     UUID NOT NULL,
  host          TEXT NOT NULL,               -- the canonical target host this slot is held for
  owner         TEXT NOT NULL,               -- the broker instance holding the lease (for operability/audit)
  acquired_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,        -- the lease deadline: a slot counts ONLY while expires_at > now()
  PRIMARY KEY (id),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
-- The hot path is "count live slots for (engagement, host)"; the sweeper scans by deadline.
CREATE INDEX host_slot_live_idx  ON host_slot (engagement_id, tenant_id, host);
CREATE INDEX host_slot_deadline_idx ON host_slot (expires_at);

-- Acquire one per-host slot for p_host (lease id p_slot_id, valid p_ttl_ms), or RAISE a fixed reason. Live slots for
-- (engagement, host) — those with expires_at > now(), so a crashed owner's expired lease never blocks — must be strictly
-- below per_host_concurrency. The count-then-insert runs under the per-engagement runtime-counter lock so it cannot
-- race another draw into an over-admit. On a refusal nothing is inserted (fail-closed).
CREATE FUNCTION acquire_host_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_host       TEXT,
  p_owner      TEXT,
  p_slot_id    UUID,
  p_ttl_ms     INT
) RETURNS void AS $$
DECLARE
  v_cap  INT;
  v_live INT;
BEGIN
  -- Read the cap FIRST so a missing/other-tenant engagement fails closed with a clean reason (before any side effect).
  SELECT per_host_concurrency INTO v_cap
    FROM engagement WHERE id = p_engagement AND tenant_id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  -- Serialise this engagement's admissions on the runtime-counter row (get-or-create + lock), as 0006 does.
  INSERT INTO engagement_runtime_counter (engagement_id, tenant_id, window_started_at)
    VALUES (p_engagement, p_tenant, now())
    ON CONFLICT (engagement_id) DO NOTHING;
  PERFORM 1 FROM engagement_runtime_counter
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant FOR UPDATE;

  -- Count only LIVE slots (unexpired): a crashed owner's stale lease is reclaimable capacity, so it must not block.
  SELECT count(*) INTO v_live FROM host_slot
    WHERE engagement_id = p_engagement AND host = p_host AND expires_at > now();
  IF v_live >= v_cap THEN
    RAISE EXCEPTION 'host_concurrency_exceeded';
  END IF;

  INSERT INTO host_slot (id, engagement_id, tenant_id, host, owner, expires_at)
    VALUES (p_slot_id, p_engagement, p_tenant, p_host, p_owner,
            now() + (p_ttl_ms || ' milliseconds')::interval);
END; $$ LANGUAGE plpgsql;

-- Release a held slot on completion: delete the lease. Idempotent — a slot already reclaimed by the sweeper (or a
-- double release) is a no-op, so a late release after a crash-expiry never errors. Frees capacity immediately.
CREATE FUNCTION release_host_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_slot_id    UUID
) RETURNS void AS $$
BEGIN
  DELETE FROM host_slot
    WHERE id = p_slot_id AND engagement_id = p_engagement AND tenant_id = p_tenant;
END; $$ LANGUAGE plpgsql;

-- Reclaim every expired slot lease (table-size housekeeping) and return how many were removed. Safety never depends on
-- this running: acquire already ignores expired slots. INVOCATION: a SYSTEM, owner-agnostic maintenance job; run it as
-- an RLS-EXEMPT system role so it reclaims across ALL engagements/tenants (a per-tenant call under FORCE RLS would only
-- clear its own tenant's rows — harmless, just leaves other tenants' housekeeping undone), exactly like sweep_expired_leases (0005).
CREATE FUNCTION sweep_expired_slots() RETURNS integer AS $$
DECLARE
  n integer;
BEGIN
  WITH swept AS (
    DELETE FROM host_slot WHERE expires_at <= now() RETURNING 1
  )
  SELECT count(*) INTO n FROM swept;
  RETURN n;
END; $$ LANGUAGE plpgsql;

ALTER TABLE host_slot ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_slot FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON host_slot
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
