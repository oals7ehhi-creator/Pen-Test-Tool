-- =============================================================================================================
-- 0009  WebSocket connection admission: ws_in_flight <= max_ws_connections  (Phase 2 slice 5g; Phase 0 doc 04 §8 / §7.2)
-- -------------------------------------------------------------------------------------------------------------
-- The WebSocket admission interlock. A kind='websocket' spec authorizes only the HTTP Upgrade handshake, scoped /
-- resolved / IP-pinned / connected EXACTLY like an HTTP request; on a successful handshake the broker holds ONE
-- connection slot for the engagement, and the number of live slots may never exceed `engagement.max_ws_connections`
-- (the authoritative `ws_in_flight`, §8). Like the per-host concurrency slots (0008) this is a CRASH-SAFE LEASE — a slot
-- counts only while unexpired, so a broker that crashes mid-connection stops occupying its slot when the lease expires.
--
-- LEASE LIFETIME: bounded to the connection's MAX permitted lifetime, `ws_max_duration_s` (the DB derives it, so the
-- caller cannot over-lease). A well-behaved connection is terminated by the per-connection governor (slice 5f,
-- `evaluateWsFrame`) at or before that bound and RELEASES its slot early on close; a crashed broker's slot self-heals at
-- the bound WITHOUT any heartbeat. (`max_ws_connections` is small — 0..64 — so a stranded slot's liveness cost is
-- modest, and a stranded slot only makes admission STRICTER, never unsafe.) A cap of 0 disables WebSockets entirely
-- (0 >= 0 refuses every acquire).
--
-- Mirrors the pure `evaluateWsAdmission` logic in @pentest/broker (wsadmit.ts); the atomic count-under-lock + insert
-- lives here so the broker package stays I/O-free. ADMISSION SERIALISATION: the count-then-insert runs under the
-- per-engagement runtime-counter FOR UPDATE lock (get-or-created, as 0006/0008 do) so concurrent handshakes cannot
-- over-admit. A refusal RAISEs a fixed reason and persists nothing (fail-closed). SECURITY INVOKER — RLS scopes every
-- function to the broker's tenant. Extension-free; the down migration drops the table + all three functions.
--
-- SCOPE: connection ADMISSION only. The per-connection duration/count/size envelope is slice 5f; the outbound-frame
-- source restriction to the approved content-addressed `ws_frame_set` (SI-063) is a later slice; e-stop / window-close /
-- expiry termination of active connections is the live-state gate's job (slice 5b), re-checked out of band.
-- =============================================================================================================

CREATE TABLE ws_slot (
  id            UUID NOT NULL,                -- caller-supplied lease handle (broker: crypto.randomUUID), as budget_reservation / host_slot
  engagement_id UUID NOT NULL,
  tenant_id     UUID NOT NULL,
  owner         TEXT NOT NULL,               -- the broker instance holding the connection (for operability/audit)
  acquired_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,        -- the lease deadline (now() + ws_max_duration_s); a slot counts ONLY while expires_at > now()
  PRIMARY KEY (id),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
-- The hot path is "count live slots for the engagement"; the sweeper scans by deadline.
CREATE INDEX ws_slot_live_idx     ON ws_slot (engagement_id, tenant_id);
CREATE INDEX ws_slot_deadline_idx ON ws_slot (expires_at);

-- Acquire one WebSocket connection slot for the engagement (lease id p_slot_id), or RAISE a fixed reason. Live slots
-- (expires_at > now(), so a crashed owner's expired lease never blocks) must be strictly below max_ws_connections. The
-- lease deadline is derived from ws_max_duration_s — the connection's max permitted lifetime — so the caller cannot
-- over-lease. Count-then-insert under the per-engagement runtime lock cannot race into an over-admit; on refusal nothing
-- is inserted (fail-closed).
CREATE FUNCTION acquire_ws_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_owner      TEXT,
  p_slot_id    UUID
) RETURNS void AS $$
DECLARE
  v_cap   INT;
  v_dur_s INT;
  v_live  INT;
BEGIN
  -- Read the caps FIRST so a missing/other-tenant engagement fails closed with a clean reason (before any side effect).
  SELECT max_ws_connections, ws_max_duration_s INTO v_cap, v_dur_s
    FROM engagement WHERE id = p_engagement AND tenant_id = p_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'unknown_engagement';
  END IF;

  -- Serialise this engagement's admissions on the runtime-counter row (get-or-create + lock), as 0006/0008 do.
  INSERT INTO engagement_runtime_counter (engagement_id, tenant_id, window_started_at)
    VALUES (p_engagement, p_tenant, now())
    ON CONFLICT (engagement_id) DO NOTHING;
  PERFORM 1 FROM engagement_runtime_counter
    WHERE engagement_id = p_engagement AND tenant_id = p_tenant FOR UPDATE;

  -- Count only LIVE slots (unexpired): a crashed owner's stale lease is reclaimable capacity, so it must not block. A
  -- cap of 0 refuses every acquire here (0 >= 0), disabling WebSockets for the engagement.
  SELECT count(*) INTO v_live FROM ws_slot
    WHERE engagement_id = p_engagement AND expires_at > now();
  IF v_live >= v_cap THEN
    RAISE EXCEPTION 'ws_connection_limit';
  END IF;

  INSERT INTO ws_slot (id, engagement_id, tenant_id, owner, expires_at)
    VALUES (p_slot_id, p_engagement, p_tenant, p_owner, now() + (v_dur_s || ' seconds')::interval);
END; $$ LANGUAGE plpgsql;

-- Release a held connection slot on close: delete the lease. Idempotent — a slot already reclaimed by the sweeper (or a
-- double release) is a no-op, so a late release after a crash-expiry never errors. Frees capacity immediately.
CREATE FUNCTION release_ws_slot(
  p_tenant     UUID,
  p_engagement UUID,
  p_slot_id    UUID
) RETURNS void AS $$
BEGIN
  DELETE FROM ws_slot
    WHERE id = p_slot_id AND engagement_id = p_engagement AND tenant_id = p_tenant;
END; $$ LANGUAGE plpgsql;

-- Reclaim every expired connection slot (table-size housekeeping) and return how many were removed. Safety never
-- depends on this running: acquire already ignores expired slots. INVOCATION: a SYSTEM, owner-agnostic maintenance job;
-- run it as an RLS-EXEMPT system role so it reclaims across ALL engagements/tenants, exactly like sweep_expired_leases
-- (0005) / sweep_expired_slots (0008).
CREATE FUNCTION sweep_expired_ws_slots() RETURNS integer AS $$
DECLARE
  n integer;
BEGIN
  WITH swept AS (
    DELETE FROM ws_slot WHERE expires_at <= now() RETURNING 1
  )
  SELECT count(*) INTO n FROM swept;
  RETURN n;
END; $$ LANGUAGE plpgsql;

ALTER TABLE ws_slot ENABLE ROW LEVEL SECURITY;
ALTER TABLE ws_slot FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ws_slot
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
