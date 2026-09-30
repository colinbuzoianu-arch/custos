create table gateways (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    name text not null,
    -- Only ever the SHA-256 hash of the gateway's own credential to
    -- Control - the gateway itself holds the plaintext (it has to, to
    -- present it), Control never sees it again after enrollment. Same
    -- convention as agents.token_sha256, roles reversed: here the gateway
    -- is the one authenticating itself to Control.
    credential_sha256 text not null,
    enrolled_at timestamptz not null default now(),
    last_heartbeat_at timestamptz,
    last_version text,
    -- The gateway's own policy hash (custos_policy::Versioned::version, a
    -- SHA-256 hex digest of its concatenated policy source) - not the same
    -- number as policy_versions.version, which is Control's per-tenant
    -- publish counter. This is what the gateway is actually enforcing.
    last_policy_version text,
    decisions_allowed bigint not null default 0,
    decisions_blocked bigint not null default 0,
    unique (tenant_id, name)
);

-- One-time tokens an admin issues out of band (e.g. to paste into a
-- gateway's `custos enroll` command). Single-use: `used_at` is set the
-- moment they're consumed and never accepted again.
create table gateway_enroll_tokens (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references tenants (id) on delete cascade,
    token_sha256 text not null unique,
    created_by_user_id uuid references users (id) on delete set null,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null default now()
);

-- The exact signed bytes produced at publish time, frozen - served back to
-- every gateway that polls, never regenerated (regenerating could produce
-- different bytes for the same version if agents changed since publish,
-- which would defeat the point of a version being a fixed, signed
-- snapshot).
alter table policy_versions add column bundle_json text;
alter table policy_versions add column bundle_signature text;
