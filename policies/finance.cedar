// Example policies. Model: principal Agent, action "call_tool", resource Tool.
// Default is deny: anything not permitted below is blocked.

@id("invoice-processor-read")
permit (
    principal == Agent::"invoice-processor",
    action == Action::"call_tool",
    resource
) when {
    [Tool::"sap.read_invoice",
     Tool::"sap.read_vendor",
     Tool::"sap.create_payment_proposal"].contains(resource)
};

@id("no-payment-execution")
forbid (
    principal,
    action == Action::"call_tool",
    resource == Tool::"sap.execute_payment"
);

@id("no-payroll")
forbid (
    principal,
    action,
    resource == Tool::"payroll.read_salaries"
);

// `@hold` turns what would otherwise be an Allow into a wait-for-a-human
// decision (session 16) - the gateway asks Custos Control and blocks if
// nobody approves it within `approval_timeout_secs`. `@four_eyes` (no
// value needed) additionally stops the agent's own owner from being the
// one who approves it.
@id("large-vendor-payment-needs-approval")
@hold("vendor payment proposal requires a human approver")
@four_eyes
permit (
    principal == Agent::"invoice-processor",
    action == Action::"call_tool",
    resource == Tool::"sap.approve_vendor_payment"
);
