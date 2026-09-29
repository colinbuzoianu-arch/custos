# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Custos is pre-1.0: expect breaking changes between minor versions.

## [0.1.0] — Unreleased

First tagged release. A runtime firewall for one MCP agent talking to one
upstream MCP server, enforced by Cedar policy, with a tamper-evident audit
trail.

### Gateway

- Proxies the MCP streamable-HTTP transport (`POST`/`GET`/`DELETE /mcp`) to
  one upstream server.
- Agents authenticate with a bearer token, stored and compared only as its
  SHA-256 hash — the plain token is never held anywhere.
- `tools/list` responses are filtered to the tools an agent's policy allows,
  for both `application/json` and `text/event-stream` upstream replies; a
  response shape or content-type the gateway doesn't recognize fails closed.
- MCP sessions are bound to the agent that created them: another agent
  reusing that session id gets `403` (audited as a reuse attempt) and is
  never forwarded; an unknown session id gets `404`. Idle sessions expire
  (default 24h) and the session table is capped (default 10,000, LRU
  eviction).
- Fails closed throughout: unparseable bodies, JSON-RPC batches, a missing
  tool name, or an audit-log write failure all block the call rather than
  letting it through.

### Policy

- Cedar-based authorization: `Agent::"<id>"` calling `Action::"call_tool"` on
  `Tool::"<name>"`. Default deny — a call is allowed only if some `permit`
  matches and no `forbid` does. Every decision names the `@id` of the policy
  (or policies) that decided it.
- `custos check-policy <dir>` validates every `*.cedar` file individually,
  attributing each syntax error to its file and (where Cedar's diagnostics
  provide one) a line number; warns, without failing, about any policy with
  no `@id` annotation.
- Policies reload without restarting: `SIGHUP` on Unix, or a debounced file
  watcher behind `--watch-policies` (cross-platform). A reload is loaded and
  fully validated before it replaces the running policy set — on failure the
  previous set keeps deciding calls, never falling back to "no policy." A
  request in flight when a reload lands finishes with the policy version it
  started with.

### Audit log

- Append-only JSON Lines, hash-chained: every record includes the hash of
  the one before it, so an edit, insertion, or deletion breaks the chain
  from that point on. `custos verify-audit <path>` checks the whole chain.
- Tool-call arguments are never stored raw by default. `audit_arguments`
  picks one of three modes: `hash` (default) — an HMAC-SHA256 of the
  canonicalized arguments plus their byte size, keyed by `CUSTOS_AUDIT_KEY`
  (never held in config); `redacted` — the same JSON shape and keys, every
  value replaced by its type and length; `full` — arguments as-is, with a
  startup warning that this may store personal data.
- Every record also carries the agent's configured `owner`, a
  `gateway_instance` id (config, default the machine's hostname), and the
  `policy_version` (a hash of the exact policy source) that decided it.
- Audit writes run off the async runtime (`tokio::task::spawn_blocking`),
  while the gateway still waits for the write to complete and flush before
  acting on the decision.
- Records from earlier, narrower versions of this format (no `policy_version`
  field, or no version field at all) still verify — the chain doesn't need
  a fresh log to upgrade.

### Operations

- Distroless, non-root Docker image; `docker-compose.yml` demo with the MCP
  reference "everything" server. `custos healthcheck` backs the container
  `HEALTHCHECK`, since the image has no shell or `curl`.
- `docs/DEMO.md` walks the same scenario two ways: Docker, or `cargo run` in
  three terminals.

### Known limitations

- `Hold` decisions (wait for human approval) parse but aren't enforced yet —
  handled identically to `Block`.
- One gateway, one upstream, one policy directory. No multi-tenant control
  plane, no dashboard, no signed policy bundles.
- No content inspection (IBAN, CNP, API keys, ...) inside arguments yet.
- Bearer tokens are static and don't expire; no OAuth 2.1 yet.
