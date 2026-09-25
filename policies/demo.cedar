// Demo policy for the "everything" MCP reference server (npm package
// @modelcontextprotocol/server-everything). Used by docs/DEMO.md.
// Default is deny: anything not permitted below is blocked, including every
// "everything" tool not named here (e.g. toggle-simulated-logging).

@id("demo-agent-safe-tools")
permit (
    principal == Agent::"demo-agent",
    action == Action::"call_tool",
    resource
) when {
    [Tool::"echo", Tool::"get-sum"].contains(resource)
};

@id("demo-agent-no-env-dump")
forbid (
    principal,
    action == Action::"call_tool",
    resource == Tool::"get-env"
);
