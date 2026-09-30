-- Per-gateway chain-continuity tracking. Control doesn't re-derive the
-- gateway's own SHA-256 hash chain (that logic is versioned and lives in
-- custos-audit) - it only checks that each newly ingested record's
-- (seq, prev_hash) is exactly what should follow the last one it saw, and
-- flags the gateway if not. Once flagged, later good records don't quietly
-- clear the flag - a real gap or break stays visible until an operator
-- looks at it.
alter table gateways add column last_ingested_seq bigint;
alter table gateways add column last_ingested_hash text;
alter table gateways add column chain_status text not null default 'ok'
    check (chain_status in ('ok', 'gap', 'broken'));
alter table gateways add column chain_issue text;

-- One row per shipped audit record. `record` keeps the exact JSON as
-- ingested (schema-tolerant: whatever version the gateway wrote); the other
-- columns are a best-effort extraction of what the search API filters on,
-- nullable because a malformed or unexpected-shape record must still be
-- stored, never dropped.
create table audit_records (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    gateway_id uuid not null references gateways (id) on delete cascade,
    seq bigint not null,
    ts timestamptz,
    agent text,
    owner text,
    tool text,
    verdict text,
    policy_version text,
    findings jsonb,
    record jsonb not null,
    ingested_at timestamptz not null default now(),
    -- The idempotency key: re-shipping the same (gateway_id, seq) is a
    -- no-op, never a duplicate row.
    unique (gateway_id, seq)
);

create index audit_records_search_idx on audit_records (tenant_id, ts desc, id desc);
create index audit_records_agent_idx on audit_records (tenant_id, agent);
create index audit_records_tool_idx on audit_records (tenant_id, tool);
create index audit_records_verdict_idx on audit_records (tenant_id, verdict);
create index audit_records_policy_version_idx on audit_records (tenant_id, policy_version);
