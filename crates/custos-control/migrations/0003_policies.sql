create table policy_versions (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    version integer not null,
    policy_text text not null,
    schema_text text,
    author_user_id uuid references users (id) on delete set null,
    message text,
    -- Whether this version parses and (if a schema is set) type-checks.
    -- An invalid draft is still saved so nothing is lost, it just can't be
    -- published - see custos_policy::validate_source.
    valid boolean not null default false,
    validation_error text,
    published boolean not null default false,
    published_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, version)
);

create index policy_versions_tenant_created_at_idx on policy_versions (tenant_id, created_at);
