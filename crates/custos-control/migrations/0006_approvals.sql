-- A gateway creates one of these when a Cedar policy's @hold annotation
-- turns an Allow into a wait-for-a-human decision, then polls it (session
-- 16 does gateway-side polling, not true server long-poll - see
-- docs/decisions/0008-hold-and-approval.md) until it leaves 'pending' or
-- its own timeout elapses.
create table approvals (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    gateway_id uuid not null references gateways (id) on delete cascade,
    agent text not null,
    tool text not null,
    -- What custos_inspect found in the arguments - kind/path/count only,
    -- never the raw arguments, same guarantee as the audit log.
    findings jsonb,
    reason text not null,
    -- Set when the deciding policy also carried @four_eyes: the agent's
    -- own owner (agents.owner_user_id) then can't be the one who resolves
    -- this approval.
    four_eyes boolean not null default false,
    status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
    approver_user_id uuid references users (id) on delete set null,
    comment text,
    created_at timestamptz not null default now(),
    resolved_at timestamptz
);

create index approvals_tenant_status_idx on approvals (tenant_id, status, created_at);
