# Architecture

```
 agent ──HTTP (MCP)──▶  CUSTOS GATEWAY  ──HTTP (MCP)──▶ MCP server ──▶ tools / data
                         │
                         ├─ 1 identify   bearer token → sha256 → AgentId      (401 if unknown)
                         ├─ 2 parse      single JSON-RPC object only           (400 otherwise)
                         ├─ 3 decide     tools/call → Cedar → Allow / Block
                         ├─ 4 record     append + fsync hash-chained record   (503 if it fails)
                         └─ 5 forward    allow-listed headers, upstream creds, stream body back
```

Messages other than `tools/call` (initialize, tools/list, notifications) are
forwarded after authentication. `tools/list` filtering is planned (PLAN, session 3).

## Policy model (v0)

| Cedar part | Value |
|---|---|
| principal | `Agent::"<agent id from config>"` |
| action | `Action::"call_tool"` |
| resource | `Tool::"<tool name>"` |

Later versions add entity hierarchies (`Tool` in `Domain::"finance"`), request
context (inspection results, time) and `@hold` annotations.

## Blocked call response

A block returns HTTP 200 with a JSON-RPC error so the agent's MCP client
handles it normally and the model can see why:

```json
{"jsonrpc":"2.0","id":8,"error":{"code":-32001,"message":"Blocked by Custos: forbidden by no-payroll"}}
```

## Audit record

```json
{"seq":2,"ts":"2026-09-24T12:40:00Z","call":{"agent":"invoice-processor","tool":"payroll.read_salaries","arguments":{}},
 "decision":{"verdict":"BLOCK","reason":"forbidden by no-payroll"},"prev_hash":"…","hash":"…"}
```

`hash = sha256(json(seq, ts, call, decision, prev_hash))`. Any edit, insert or
deletion breaks the chain from that line on.

## Stack

| Layer | Choice |
|---|---|
| Gateway, control API | Rust, Tokio, axum, reqwest |
| Policy | Cedar (`cedar-policy`) |
| Config / tenants | PostgreSQL (control plane) |
| Audit at scale | ClickHouse (control plane) |
| Dashboard | Next.js + TypeScript |
| Deploy | single binary / distroless Docker; EU (Frankfurt) hosted control plane |

See `docs/decisions/0001-stack.md` for why.
