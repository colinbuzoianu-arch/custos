# Demo: a real agent through Custos

This walks a real MCP server (the official reference "everything" server)
through Custos, with one tool allowed, one explicitly forbidden, and one
blocked by default deny. Two ways to run it: Docker (below, fastest) or
three terminals with `cargo run` (further down, better for reading logs live
and poking at the code).

## Docker in 2 commands

Prerequisites: Docker with Compose.

```bash
cp .env.example .env
docker compose up
```

That builds the gateway image, starts the "everything" server (not exposed
outside the compose network — only Custos can reach it) and Custos itself,
reachable at `http://127.0.0.1:8787/mcp` with the same demo token as below
(`custos-demo-token`). The audit log lands in the `custos-data` named
volume; `docker compose exec custos custos verify-audit
/var/lib/custos/audit.jsonl` checks it. `docker compose down` stops
everything; add `-v` to also drop the volume.

This uses `config/custos.docker.toml` (`audit_arguments = "redacted"`, no
signing key needed) rather than the config you'd hand-build below — see that
file's comments, and `config/custos.example.toml`, for the production
`"hash"` mode.

## Full stack: gateway + Control

This runs the gateway *and* Custos Control together: an agent and a policy
created through Control's API, a gateway that enrolls with Control and
syncs both down automatically (not a static config file), and the gateway
shipping its audit log back to Control.

Prerequisites: Docker with Compose, `curl`, and [`jq`](https://jqlang.org/)
(the seed script parses JSON responses with it — `apt install jq` /
`brew install jq` / `choco install jq`, or on Windows without Chocolatey,
`winget install jqlang.jq`).

```bash
cp .env.example .env
export CUSTOS_CONTROL_POLICY_SIGNING_KEY=$(openssl rand -hex 32)

docker compose -f docker-compose.yml -f docker-compose.control.yml -f docker-compose.full.yml \
  up -d everything postgres control

./scripts/seed-demo.sh
```

The seed script (`scripts/seed-demo.sh`) creates a Control admin, logs in,
creates an agent and issues its token, saves and publishes a policy
granting that agent `echo`/`get-sum` (same two tools as the plain demo),
creates a one-time gateway enrollment token, runs `custos enroll` inside a
throwaway container using it, and finally starts the real gateway — all
against the same Postgres-backed Control instance, reachable at
`http://127.0.0.1:8788`. It prints the agent's token at the end (shown
once, same guarantee as the dashboard's "issue token" button).

Give the gateway a few seconds (it polls Control every 5s —
`config/custos.full.toml`) to complete its first sync, then drive it
exactly like the plain demo's [step 4](#4-terminal-3--drive-it-as-the-agent),
using the printed token, agent name `invoice-processor`, and the same
`http://127.0.0.1:8787/mcp` base URL. `docker compose -f docker-compose.yml
-f docker-compose.control.yml -f docker-compose.full.yml logs -f custos`
shows the sync happening and each decision as it's made.

What this demonstrates that the plain Docker demo doesn't:

- **The agent's token came from Control**, not a hash hand-computed and
  pasted into a config file — this gateway has no `[[agents]]` of its own
  at all (`config/custos.full.toml`).
- **The policy came from Control**, published through its API, not a
  `.cedar` file baked into the image or bind-mounted from the repo.
- **The audit log round-trips**: every decision the gateway makes is
  shipped to Control and searchable there (`GET /api/audit` once you're
  logged in — no dashboard page serves this yet, see
  `docs/decisions/0006-dashboard.md`'s open item on embedding it).

To look at Control's own data directly (agents, policies, audit, pending
approvals) without the dashboard, use its API with the same cookie jar the
seed script builds, or log in fresh with the admin credentials the script
used (`admin@demo.test` / `correct-horse-battery-staple` — demo-only,
same caveat as the plain demo's token).

**This hasn't been run against a live Docker daemon in the environment it
was written in** (no Docker available there, the same limitation as the
Postgres-backed tests throughout this project) — if a step fails, please
say what broke so it can be fixed.

`docker compose -f docker-compose.yml -f docker-compose.control.yml -f docker-compose.full.yml down -v`
tears down everything including both named volumes (gateway state and the
Postgres database).

## cargo run, three terminals

This walks the same scenario by hand: Node.js (for `npx`) and Rust
(`cargo test --workspace` already passing), all from the repo root
(`custos/`).

## 1. Create the local config

`config/custos.toml` is git-ignored — it never gets committed — so create it
yourself:

```toml
listen = "127.0.0.1:8787"
upstream = "http://127.0.0.1:3001/mcp"

policy_dir = "policies"
audit_log = "data/audit.jsonl"

# "redacted" keeps the demo simple (no signing key to generate). Production
# should use the default "hash" mode instead — see config/custos.example.toml
# and docs/ARCHITECTURE.md ("Recording arguments without recording personal
# data") for what that needs.
audit_arguments = "redacted"

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
