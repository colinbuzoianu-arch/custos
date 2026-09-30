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
- [x] Install rustup, VS Code, extensions from `.vscode/extensions.json`, Claude Code
- [x] `cargo test --workspace` passes locally
- [x] Create a private GitHub repo, push, check the CI workflow goes green
- [x] Add the Apache-2.0 `LICENSE` file (GitHub's "Add file → license template")
- [x] Ask Claude Code `/explain crates/custos-gateway/src/lib.rs` and read the request path once end to end

### Session 2 — first real agent through Custos
- [x] Run a real MCP server locally (e.g. the MCP reference "everything" server in streamable-HTTP mode)
- [x] Copy `config/custos.example.toml` to `config/custos.toml`, point `upstream` at it, create a token with `hash-token`
- [x] Connect Claude Code (or Claude Desktop) to `http://127.0.0.1:8787/mcp` with the agent token as a header
- [x] Watch allowed and blocked calls in the log; run `verify-audit`
- [x] Write `docs/DEMO.md` with the exact steps (becomes the README quick-start)

### Session 3 — agents only see what they may use
- [x] Filter `tools/list` responses: remove tools the agent's policy would block
- [x] Handle both response types: `application/json` and `text/event-stream` (SSE)
- [x] Tests: filtered list, SSE case, unknown content-type fails closed

### Session 4 — audit that respects GDPR
- [x] Stop storing raw tool arguments by default: store a SHA-256 of the arguments plus a size
- [x] Config switch `audit_arguments = "hash" | "redacted" | "full"`
- [x] Add agent `owner` and gateway instance id to each record
- [x] Move audit writes off the async runtime (`spawn_blocking` or a writer task + channel)

### Session 5 — operable
- [x] `custos check-policy <dir>`: parse and report errors without starting
- [x] Reload policies on `SIGHUP` without dropping connections
- [x] Bind MCP session ids to the agent that created them (agent B must not reuse agent A's session)
- [x] Dockerfile (distroless, non-root) + `docker compose` demo with an MCP server
- [ ] Tag `v0.1.0`

## Phase 2 — Gateway, part 2

Each session = one branch/commit, `/check` green, `/security-review` before commit.

### Session 6 — content inspection
- [x] New crate `custos-inspect`: pure functions, no I/O, `inspect(&serde_json::Value) -> Findings`.
- [x] Detectors: IBAN (with mod-97 checksum), payment cards (Luhn), Romanian CNP (checksum),
      German Steuer-ID (checksum), email addresses, API keys/secrets (common prefixes like
      `sk-`, `ghp_`, `AKIA`, plus high-entropy strings), bulk size (argument bytes, array length).
- [x] Walk nested JSON; cap depth and total bytes inspected (config) so hostile input can't slow the gateway.
- [x] Findings contain only kind + count + JSON path, never the matched value.
- [x] Record findings in the audit record (kinds and counts only).
- Tests: valid and invalid checksums for each detector, nested/array input, oversized input
  hits the cap and fails closed, matched values never appear in findings or audit.

### Session 7 — inspection results in policy
- [x] Pass Cedar `context`: `findings` (set of kinds, e.g. `"iban"`), `args_bytes`, `array_max_len`,
      `hour_utc`, `weekday`.
- [x] Add a Cedar schema file (`policies/custos.cedarschema`) and validate policies against it in
      `check-policy` and on reload. Unknown attributes = error.
- [x] Example policies: forbid any call whose findings contain `card` or `secret`;
      forbid `crm.*` exports with `array_max_len > 500`.
- Tests: same tool allowed without findings and blocked with them; schema catches a typo.

### Session 8 — short-lived agent tokens
- [x] `custos issue-token --agent <id> --ttl 1h`: signed token (Ed25519, compact format with
      agent id, issued-at, expiry, key id). Gateway verifies signature and expiry.
- [x] Keep static hashed tokens as an option (`auth = "static" | "signed"`) for simple setups.
- [x] Key rotation: gateway accepts a list of public keys by key id.
- Tests: expired token 401, wrong key 401, tampered payload 401, rotation works.
- [ ] Tag `v0.2.0` of the gateway.

## Phase 3 — Custos Control (the interface)

### Decisions (write these into docs/decisions/0002-control-plane.md in session 9)
- **Self-hosted first.** Customers run Control themselves via docker compose (Control + Postgres).
  Their audit data never leaves their network, which removes a big sales objection. Our hosted
  EU version comes later from the same code. Every table has `tenant_id` from day one.
- **One binary.** New crate `custos-control` (Rust, axum, sqlx, Postgres). The dashboard is a
  **Vite + React + TypeScript** single-page app in `dashboard/`, built and embedded into the
  control binary (rust-embed). This replaces Next.js from ADR 0001: an admin app behind a login
  doesn't need server rendering, and one binary is much simpler for customers to run.
- **Postgres for audit search**, not ClickHouse, until a customer needs more. The gateway's
  hash-chained file stays the source of truth; Control keeps a searchable copy.
- **Gateways connect out to Control** (never the other way), so customers open no inbound ports.
- **Control never holds agent tokens** in plain form and never sees raw tool arguments (only
  what the audit mode allows).
- Dashboard UI: same visual language as the landing page (ink #16181D, ivory #F4F1EA,
  rust accent #B3401A, Newsreader headings, IBM Plex Sans/Mono), follow `design/dashboard/`
  mockups if present. Languages EN/DE/RO from the start (i18n keys, no hard-coded strings).

### Session 9 — Control skeleton and login
- [x] ADR 0002. Crate `custos-control`, sqlx migrations, `docker-compose.control.yml`
      (control + postgres), `/healthz`.
- [x] Users: email + password (argon2id), roles `admin` / `approver` / `viewer`.
      `custos-control create-admin` CLI for the first user.
- [x] Sessions: server-side, HttpOnly + Secure + SameSite=Strict cookies, CSRF protection,
      login rate limiting, audit of logins.
- Tests: login ok/fail, lockout after N failures, viewer can't call admin endpoints.

### Session 10 — agents API
- [x] CRUD agents (id, name, owner user, description, status active/disabled, expiry date).
- [x] Issue/rotate an agent token from Control: shown once, stored only as hash.
- [x] Every change written to an admin audit log (who changed what, when).
- Tests: token shown once only ✓. Disabled agent's token rejected after sync — needs session 12
  (gateway enrolment/sync), not testable yet.

### Session 11 — policies API
- [ ] Policy sets stored with versions (text, author, message, created_at). Validate with Cedar
      + schema on save; invalid versions can be saved as drafts but never published.
- [ ] Publish = create a **policy bundle**: policies + schema + agent list (token hashes /
      public keys) + version, signed with Control's Ed25519 key.
- [ ] Diff between two versions (API returns a text diff).
- Tests: invalid policy can't be published; bundle signature verifies; tampered bundle fails.

### Session 12 — gateway enrolment and sync
- [ ] `custos enroll --control <url> --token <one-time enrolment token>`: gateway gets an id and
      credentials, pins Control's public key.
- [ ] Gateway polls for new bundles (ETag), verifies the signature, applies via the reload path
      from session 5a. Keeps the last good bundle on disk; if Control is unreachable it keeps
      enforcing the last good bundle (never "allow all").
- [ ] Heartbeat: version, policy_version, uptime, decision counts.
- Tests: bad signature rejected and old bundle kept; Control offline → still enforcing.

### Session 13 — audit shipping
- [ ] Gateway ships audit records to Control in batches, with retry and backoff; local file is
      the buffer, nothing is lost if Control is down. Idempotent by (gateway_id, seq).
- [ ] Control checks chain continuity per gateway and flags gaps or broken hashes.
- [ ] Search API: filter by agent, tool, verdict, time range, policy_version; cursor pagination.
- [ ] Live stream endpoint (SSE) of new decisions for the dashboard.
- Tests: duplicate batch ignored, gap detected, search filters correct.

### Session 14 — dashboard shell
- [ ] `dashboard/` with Vite + React + TS, router, i18n (EN/DE/RO), API client with CSRF.
- [ ] Embedded in the control binary; `npm run dev` proxies to local Control for development.
- [ ] Pages: Login, Overview (decisions today, blocked %, top blocked agents/tools, gateway
      health), Agents (list, detail, create, disable, issue token).
- [ ] Accessibility: keyboard navigation, visible focus, 4.5:1 contrast.

### Session 15 — dashboard: live decisions, audit, policies
- [ ] Live decisions page (SSE stream, pause, filter), click-through to the full record.
- [ ] Audit search page with filters and CSV/JSON export.
- [ ] Policy editor: CodeMirror with Cedar highlighting, validate as you type (via API),
      version history with diff, publish button (admin only) with confirmation.

### Session 16 — hold and human approval
- [ ] Cedar annotation `@hold("reason")` on a permit: matching calls become `Hold`.
- [ ] Gateway creates an approval request in Control and waits (long-poll) up to a timeout
      (config, default 120 s). Approved → forward. Rejected or timeout → block. Control
      unreachable → block. Every step audited.
- [ ] Approvals page: pending queue, agent/tool/findings (never raw arguments unless audit
      mode allows), approve/reject with comment, only `approver`/`admin` roles.
- [ ] The approver can't be the agent's owner if `four_eyes = true` in the policy.
- Tests: approve, reject, timeout, Control down, wrong role.

### Session 17 — evidence export
- [ ] Evidence pack for a time range: PDF report (EN/DE/RO) with agent inventory, active policies
      and versions, decision statistics, approvals with approver names, chain-integrity result;
      plus a signed JSON bundle of the underlying records.
- [ ] Map sections to EU AI Act (human oversight, record-keeping), NIS2 (access control) and
      GDPR (data minimisation) with a disclaimer that this is evidence, not a compliance verdict.

### Session 18 — release
- [ ] End-to-end demo in docker compose: MCP server + gateway + Control + Postgres + seeded
      demo data. Update docs/DEMO.md.
- [ ] Security pass: `/security-review` on the whole control crate, `cargo audit`, `npm audit`.
- [ ] Tag `v0.3.0` — first version with the interface.

## Later
- [ ] OIDC login (Microsoft Entra ID, Google) for the dashboard
- [ ] Hosted EU (Frankfurt) multi-tenant Control
- [ ] LLM API egress proxy (OpenAI/Anthropic calls)
- [ ] Optional Claude Haiku judge for ambiguous content (never in the default blocking path)
- [ ] Formal policy analysis ("can any agent ever reach payroll?")
- [ ] Notifications for pending approvals (email, Slack, Teams)
