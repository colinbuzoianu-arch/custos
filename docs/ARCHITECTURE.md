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

Messages other than `tools/call` are forwarded after authentication.
`tools/list` responses are filtered to the tools this agent's policy allows,
for both `application/json` and `text/event-stream` upstream replies.

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
{"v":2,"seq":2,"ts":"2026-09-24T12:40:00Z",
 "agent":"invoice-processor","owner":"finance-lead","tool":"payroll.read_salaries",
 "arguments":{"args_hmac":"…","args_bytes":47,"key_id":"2026-01"},
 "decision":{"verdict":"BLOCK","reason":"forbidden by no-payroll"},
 "gateway_instance":"gw-01","prev_hash":"…","hash":"…"}
```

`hash = sha256(json(v, seq, ts, agent, owner, tool, arguments, decision,
gateway_instance, prev_hash))`. Any edit, insert or deletion breaks the chain
from that line on. Records written before this field set existed have no
`"v"` field and are still read with their original hashing rule — `verify`
understands both.

### Recording arguments without recording personal data

`arguments` never holds the raw tool-call arguments by default. Config's
`audit_arguments` picks one of three shapes, chosen per gateway (not
per-record):

| Mode | `arguments` holds | Needs a key? |
|---|---|---|
| `hash` (default) | `{"args_hmac", "args_bytes", "key_id"}` | yes |
| `redacted` | same JSON shape and keys, every value replaced by its type and length, e.g. `{"iban": "<string:22>"}` | no |
| `full` | the arguments, unchanged | no — but may store personal data; logs a warning at startup |

`hash` mode uses **HMAC-SHA256**, not plain SHA-256: a plain hash of a short,
guessable value (an IBAN, a CNP, an email) can be brute-forced by hashing
candidate values and comparing — HMAC mixes in a secret key so a guess is
useless without it. The key comes only from the `CUSTOS_AUDIT_KEY`
environment variable (hex or base64, at least 32 bytes) — config holds only
`audit_key_id`, an operator-chosen label identifying *which* key is loaded,
never the key itself. If `audit_arguments = "hash"` and the key is missing or
too short, the gateway refuses to start rather than silently falling back to
a weaker mode. Arguments are canonicalized (object keys sorted, recursively)
before hashing, so the same logical arguments always produce the same
`args_hmac` regardless of the order an agent sent them in.

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
