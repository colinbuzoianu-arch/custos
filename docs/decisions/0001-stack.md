# 0001 — Rust gateway, Cedar policy, TypeScript dashboard

Date: 2026-09-24 · Status: accepted

## Context
The gateway sits inline on every agent tool call. It must add little latency,
be memory-safe, ship as one binary customers can self-host, and be credible to
security buyers. Policies must be fast to evaluate and analysable.

## Decision
- **Rust** for the gateway and control API. Memory safety without a garbage
  collector, predictable latency, single static binary. The strict compiler
  also catches mistakes in AI-assisted code before they ship.
- **Cedar** for policy. Purpose-built for authorization, fast, default-deny,
  and designed for formal analysis. Preferred over OPA/Rego for this use.
- **Raw JSON-RPC passthrough** instead of a full MCP SDK in v0. A proxy only
  needs to read `method` and `params.name`; passing bytes through keeps us
  compatible with protocol changes. Revisit when we need to rewrite messages
  beyond `tools/list` filtering.
- **TypeScript/Next.js** for the dashboard only, where its UI ecosystem wins.

## Consequences
- Rust has a learning curve; CLAUDE.md asks Claude to explain new concepts.
- Two languages in the repo later (Rust + TS), split cleanly by folder.
