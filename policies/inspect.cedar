// Examples using the context custos-inspect adds to every decision (see
// docs/PLAN.md session 7, policies/custos.cedarschema). Applies to every
// agent — these are guardrails on top of, not instead of, the per-agent
// permits in the other policy files.

@id("no-card-data-in-any-call")
forbid (principal, action, resource) when {
    context.findings.contains("card")
};

// "secret" in the plan's own wording — custos-inspect's Kind serializes
// this as "api_key" (it also covers non-prefixed, high-entropy secrets).
@id("no-api-keys-in-any-call")
forbid (principal, action, resource) when {
    context.findings.contains("api_key")
};

// A concrete stand-in for "any crm.* export": Cedar can't prefix-match an
// entity id without a separate string attribute for the tool name, which
// the schema doesn't carry (see the session 7 commit message for why).
@id("no-bulk-crm-export")
forbid (
    principal,
    action,
    resource
) when {
    [Tool::"crm.export_contacts", Tool::"crm.export_deals"].contains(resource) &&
    context.array_max_len > 500
};
