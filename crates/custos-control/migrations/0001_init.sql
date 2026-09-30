-- tenant_id on every row-owning table from day one (see ADR 0002): a
-- self-hosted customer has exactly one tenant today, but the hosted
-- multi-tenant version needs no schema change to add a second.

create table tenants (
    id uuid primary key default gen_random_uuid(),
    slug text not null unique,
    name text not null,
    created_at timestamptz not null default now()
);

create table users (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    email text not null,
    password_hash text not null,
    role text not null check (role in ('admin', 'approver', 'viewer')),
    created_at timestamptz not null default now(),
    unique (tenant_id, email)
);

-- The session id itself is the opaque bearer value stored in the cookie -
-- a UUID v4 has 122 bits of randomness, which is enough entropy to be
-- unguessable used this way, so there's no need for a second token column.
create table sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users (id) on delete cascade,
    tenant_id uuid not null references tenants (id) on delete cascade,
    csrf_token text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index sessions_expires_at_idx on sessions (expires_at);

-- Every login attempt, success or failure. tenant_id is nullable: a login
-- for an email that doesn't exist in any tenant still gets audited.
create table login_audit (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid references tenants (id) on delete set null,
    email text not null,
    success boolean not null,
    ip text,
    created_at timestamptz not null default now()
);

create index login_audit_email_created_at_idx on login_audit (email, created_at);
