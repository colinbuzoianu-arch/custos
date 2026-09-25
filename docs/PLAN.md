# Custos build plan

Sessions are sized for about two focused hours each (evenings / weekends).
Work top to bottom. In Claude Code, `/next` picks up the first open box.

## Done: foundation (v0 slice)

- [x] Cargo workspace: core, policy, audit, gateway
- [x] Gateway proxies MCP streamable HTTP (POST/GET/DELETE `/mcp`) to one upstream
- [x] Agent authentication by bearer token (stored as SHA-256)
- [x] Cedar policy, default deny, blocking policy named in the error (`@id`)
- [x] Hash-chained audit log, verified on start-up and via `custos verify-audit`
- [x] Fail closed: batches, non-JSON, missing tool name, audit failure are rejected
- [x] 16 tests incl. end-to-end with a fake upstream

## Week 1: make it real

### Session 1 — set up and understand
- [ ] Install rustup, VS Code, extensions from `.vscode/extensions.json`, Claude Code
- [x] `cargo test --workspace` passes locally
- [x] Create a private GitHub repo, push, check the CI workflow goes green
- [x] Add the Apache-2.0 `LICENSE` file (GitHub's "Add file → license template")
- [ ] Ask Claude Code `/explain crates/custos-gateway/src/lib.rs` and read the request path once end to end

### Session 2 — first real agent through Custos
- [ ] Run a real MCP server locally (e.g. the MCP reference "everything" server in streamable-HTTP mode)
- [ ] Copy `config/custos.example.toml` to `config/custos.toml`, point `upstream` at it, create a token with `hash-token`
- [ ] Connect Claude Code (or Claude Desktop) to `http://127.0.0.1:8787/mcp` with the agent token as a header
- [ ] Watch allowed and blocked calls in the log; run `verify-audit`
- [ ] Write `docs/DEMO.md` with the exact steps (becomes the README quick-start)

### Session 3 — agents only see what they may use
- [ ] Filter `tools/list` responses: remove tools the agent's policy would block
- [ ] Handle both response types: `application/json` and `text/event-stream` (SSE)
- [ ] Tests: filtered list, SSE case, unknown content-type fails closed

### Session 4 — audit that respects GDPR
- [ ] Stop storing raw tool arguments by default: store a SHA-256 of the arguments plus a size
- [ ] Config switch `audit_arguments = "hash" | "redacted" | "full"`
- [ ] Add agent `owner` and gateway instance id to each record
- [ ] Move audit writes off the async runtime (`spawn_blocking` or a writer task + channel)

### Session 5 — operable
- [ ] `custos check-policy <dir>`: parse and report errors without starting
- [ ] Reload policies on `SIGHUP` without dropping connections
- [ ] Bind MCP session ids to the agent that created them (agent B must not reuse agent A's session)
- [ ] Dockerfile (distroless, non-root) + `docker compose` demo with an MCP server
- [ ] Tag `v0.1.0`

## Week 2: inspection and humans in the loop
- [ ] Content inspection on arguments: IBAN, credit cards, Romanian CNP, German tax ID, emails, API keys/secrets
- [ ] Bulk-export rule (e.g. result or argument size above a limit)
- [ ] `Hold` decisions: a Cedar annotation like `@hold("reason")` → call waits for approval via a local API
- [ ] Short-lived agent tokens with expiry; `custos issue-token`
- [ ] Policy context: time of day, argument facts from inspection, so rules can use `when { ... }`

## Weeks 3–4: control plane (commercial)
- [ ] Postgres schema: tenants, agents, owners, policies, approvals
- [ ] Control API (Rust/axum), gateways pull signed policy bundles
- [ ] ClickHouse audit sink, signed checkpoints of the hash chain
- [ ] Dashboard (Next.js/TypeScript): agent inventory, live decisions, approval queue
- [ ] Evidence export (PDF) for EU AI Act / NIS2, EN/DE/RO

## Later
- [ ] LLM API egress proxy (OpenAI/Anthropic calls, prompt data-loss checks)
- [ ] Optional Claude Haiku judge for ambiguous content (never in the default blocking path)
- [ ] Formal policy analysis ("can any agent ever reach payroll?") using Cedar's analysis tooling
- [ ] OAuth 2.1 authorization per the MCP spec instead of static bearer tokens
