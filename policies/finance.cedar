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
