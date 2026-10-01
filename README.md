# Custos

Runtime control for AI agents. Custos sits between your agents and the tools
they call. Every call is identified, checked against policy, recorded in a
tamper-evident log, and then allowed or blocked, before it happens.

**Status: early, not production-ready.** See [what's not there yet](#whats-not-there-yet).

## Quick start

### Docker

```bash
git clone https://github.com/colinbuzoianu-arch/custos.git && cd custos
cp .env.example .env
docker compose up
```

Runs Custos in front of the MCP reference "everything" server, on
`http://127.0.0.1:8787/mcp`, demo token `custos-demo-token`. See
[docs/DEMO.md](docs/DEMO.md) for what to try once it's up, and how to check
the audit log.

For the gateway *and* Custos Control together (agents, policies, and
approvals managed through Control, synced to a live gateway), see
["Full stack" in docs/DEMO.md](docs/DEMO.md#full-stack-gateway--control).

### cargo

```bash
cargo test --workspace
cp config/custos.example.toml config/custos.toml
cargo run -p custos-gateway -- hash-token my-secret-agent-token   # paste into custos.toml
cargo run -p custos-gateway -- run --config config/custos.toml
```

Point an MCP client at `http://127.0.0.1:8787/mcp` with
`Authorization: Bearer my-secret-agent-token`.

## What works

- Bearer-token agent authentication (tokens stored only as a hash).
- Cedar policy, default deny, `tools/call` and `tools/list` both enforced.
- Tamper-evident, hash-chained audit log; GDPR-respecting by default (tool
  arguments are HMAC'd, not stored raw).
- Policy reload without restart (`SIGHUP`, or `--watch-policies`).
- MCP sessions bound to the agent that created them.
- Distroless Docker image, `docker compose` demo.

## What's not there yet

- **No `Hold`/approval workflow.** The policy model parses a `Hold`
  decision, but the gateway currently treats it exactly like `Block` — there
  is no "wait for a human to approve" path yet.
- **No dashboard or control plane.** One gateway, one upstream MCP server,
  one local policy directory and audit log file. No multi-tenant management,
  no UI, no signed policy bundles distributed from a control API.
- **No content inspection.** Arguments aren't scanned for IBANs, card
  numbers, national ID numbers, API keys, etc. — that's `Hash`/`Redacted`
  audit modes protecting the *log*, not the call itself.
- **Static bearer tokens.** No expiry, no OAuth 2.1.

See [CHANGELOG.md](CHANGELOG.md) for what shipped in each release and
[docs/PLAN.md](docs/PLAN.md) for what's next.

## Docs

[Architecture](docs/ARCHITECTURE.md) · [Demo](docs/DEMO.md) ·
[Plan](docs/PLAN.md) · [Security policy](SECURITY.md)

Gateway licensed under Apache-2.0. © Verumsell SRL.
