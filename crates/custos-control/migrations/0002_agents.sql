create table agents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    name text not null,
    -- Who to contact about this agent. Nullable: the owning user might not
    -- exist yet, or might later be removed without taking the agent with it.
    owner_user_id uuid references users (id) on delete set null,
    description text,
    status text not null default 'active' check (status in ('active', 'disabled')),
    expiry_date timestamptz,
    -- Only ever the SHA-256 hash of the agent's bearer token - same
    -- convention as the gateway's own `custos hash-token`. The plaintext
    -- exists for one response, right after issuing or rotating it, and is
    -- never stored anywhere.
    token_sha256 text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (tenant_id, name)
);

-- Every admin-gated change, across every resource type - not just agents,
-- so this table doesn't need to be recreated when session 11 adds policies.
-- Never carries a token value or hash, even for token-related actions.
create table admin_audit (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    actor_user_id uuid references users (id) on delete set null,
    action text not null,
    target_type text not null,
    target_id uuid,
    detail jsonb,
    created_at timestamptz not null default now()
);

create index admin_audit_tenant_created_at_idx on admin_audit (tenant_id, created_at);
