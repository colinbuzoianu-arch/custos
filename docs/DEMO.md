# Demo: a real agent through Custos

This walks a real MCP server (the official reference "everything" server)
through Custos, with one tool allowed, one explicitly forbidden, and one
blocked by default deny. It needs three terminals open at once, all from the
repo root (`custos/`).

Prerequisites: Node.js (for `npx`), Rust (`cargo test --workspace` already
passing).

## 1. Create the local config

`config/custos.toml` is git-ignored — it never gets committed — so create it
yourself:

```toml
listen = "127.0.0.1:8787"
upstream = "http://127.0.0.1:3001/mcp"

policy_dir = "policies"
audit_log = "data/audit.jsonl"

# Agent token (plaintext, only for this demo): custos-demo-token
[[agents]]
id = "demo-agent"
owner = "colin"
token_sha256 = "198fa9f6c41121a815dbef3eb5acb40fe4182e6d29f91b2947dcd5e7e60ce439"
```

The hash was produced with:

```bash
cargo run -p custos-gateway -- hash-token custos-demo-token
```

If you want a different demo token, run that command with your own token and
put the resulting hash in the file instead — Custos only ever stores and
compares the hash, never the plain token (see `CLAUDE.md`, invariant 5).

`policies/demo.cedar` (already committed) grants `demo-agent` two harmless
tools and explicitly forbids one:

```
permit ... [Tool::"echo", Tool::"get-sum"]     # allowed
forbid ... Tool::"get-env"                      # explicitly forbidden
# everything else (e.g. toggle-simulated-logging) — default deny
```

The audit log's directory must exist before the gateway starts (it does not
create parent directories):

- **Windows (PowerShell):** `New-Item -ItemType Directory -Force data`
- **macOS/Linux:** `mkdir -p data`

## 2. Terminal 1 — start the upstream MCP server

The official reference server, in streamable-HTTP mode, listening on
`127.0.0.1:3001` by default (both platforms, same command):

```bash
npx -y @modelcontextprotocol/server-everything streamableHttp
```

Leave it running. It logs each request it receives.

## 3. Terminal 2 — start Custos

```bash
cargo run -p custos-gateway -- run --config config/custos.toml
```

You should see a `custos gateway started` line naming the listen address,
upstream, and agent count. Leave it running — this is what you'll watch for
allow/block log lines in the next step.

## 4. Terminal 3 — drive it as the agent

MCP's streamable-HTTP transport is session-based: the first call
(`initialize`) returns an `Mcp-Session-Id` header that every later call must
send back. Custos passes that header straight through (see
`FORWARD_REQUEST_HEADERS` / `FORWARD_RESPONSE_HEADERS` in
`crates/custos-gateway/src/lib.rs`) so the upstream server can track the
session; Custos itself doesn't need to.

### macOS/Linux (bash)

```bash
TOKEN="custos-demo-token"
BASE="http://127.0.0.1:8787/mcp"

# initialize — capture the session id from the response headers
SESSION_ID=$(curl -s -D - -o /tmp/init.json -X POST "$BASE" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | cut -d' ' -f2)
echo "session: $SESSION_ID"

# required "initialized" notification
curl -s -X POST "$BASE" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# allowed: echo
curl -s -X POST "$BASE" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello from the demo"}}}'

# forbidden: get-env
curl -s -X POST "$BASE" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get-env","arguments":{}}}'

# default deny: not mentioned in any policy
curl -s -X POST "$BASE" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"toggle-simulated-logging","arguments":{}}}'
```

### Windows (PowerShell)

```powershell
$Token = "custos-demo-token"
$Base = "http://127.0.0.1:8787/mcp"
$Headers = @{ Authorization = "Bearer $Token"; Accept = "application/json, text/event-stream" }

# initialize — capture the session id from the response headers
$init = Invoke-WebRequest -Uri $Base -Method POST -Headers $Headers -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}'
$SessionId = $init.Headers["Mcp-Session-Id"]
Write-Host "session: $SessionId"
$Headers["Mcp-Session-Id"] = $SessionId

# required "initialized" notification
Invoke-WebRequest -Uri $Base -Method POST -Headers $Headers -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","method":"notifications/initialized"}' | Out-Null

# allowed: echo
Invoke-WebRequest -Uri $Base -Method POST -Headers $Headers -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello from the demo"}}}' `
  | Select-Object -ExpandProperty Content

# forbidden: get-env
Invoke-WebRequest -Uri $Base -Method POST -Headers $Headers -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get-env","arguments":{}}}' `
  | Select-Object -ExpandProperty Content

# default deny: not mentioned in any policy
Invoke-WebRequest -Uri $Base -Method POST -Headers $Headers -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"toggle-simulated-logging","arguments":{}}}' `
  | Select-Object -ExpandProperty Content
```

## 5. What to look for

- **Terminal 2** (Custos) logs one line per `tools/call`: `echo` and `get-sum`
  show `decision: Allow`; `get-env` and `toggle-simulated-logging` show
  `decision: Block` with a reason naming the policy (`no-payment-execution`
  style `@id`, or "default deny" when nothing matched).
- **Terminal 1** (upstream) only ever logs the *allowed* calls — a blocked
  call never reaches it. That's the thing to actually verify: it's the
  concrete proof of invariant 2 (default deny) and invariant 3 (audit before
  acting) from `CLAUDE.md`, not just a log line saying so.
- The JSON-RPC response for a blocked call has `error.code = -32001` and a
  message starting `Blocked by Custos: ...` — that's `BLOCKED_CODE` in
  `crates/custos-gateway/src/lib.rs`.

## 6. Verify the audit trail

```bash
cargo run -p custos-gateway -- verify-audit data/audit.jsonl
```

This should print `OK: N records, chain intact`. Each line in
`data/audit.jsonl` is one decision, hash-chained to the one before it — if
any line were edited or deleted after the fact, this command would fail.
