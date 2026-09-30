# 0002 — Custos Control: self-hosted first, one binary, Postgres

Date: 2026-09-30 · Status: accepted

## Context
The gateway (Apache-2.0) enforces policy and writes a local, hash-chained
audit log per instance. Buyers running more than one gateway — or wanting a
UI instead of reading JSON Lines — need a place to manage agents, publish
policy, review decisions and approve holds across every gateway they run.
That's Custos Control: commercial, separate from the open-source gateway.

## Decision
- **Self-hosted first.** Customers run Control themselves via
  `docker-compose.control.yml` (Control + Postgres). Their audit data never
  leaves their network, which removes a sales objection security buyers
  raise early. Our hosted EU (Frankfurt) version comes later from the same
  code. Every table carries `tenant_id` from day one so that hosted version
  doesn't need a schema migration to become multi-tenant.
- **One binary.** New crate `crates/custos-control` (Rust, axum, sqlx,
  Postgres) — not a member of the gateway's Apache-2.0 grant; see its own
  `Cargo.toml` and `NOTICE.md`. The dashboard (session 14) is a Vite + React
  + TypeScript single-page app in `dashboard/`, built and embedded into this
  same binary (`rust-embed`). This replaces the Next.js dashboard from ADR
  0001: an admin app behind a login doesn't need server rendering, and one
  binary is much simpler for a customer to run than two services.
- **Postgres for audit search**, not ClickHouse, until a customer's volume
  needs more. The gateway's local hash-chained file stays the source of
  truth for tamper-evidence; Control keeps a searchable copy shipped to it
  (session 13).
- **Gateways connect out to Control**, never the other way — customers open
  no inbound ports for this.
- **Control never holds agent tokens in plain form** (agent tokens are the
  gateway's concern — static hash or signed, per session 8 — Control only
  issues/records them) **and never sees raw tool arguments**, only whatever
  the gateway's own `audit_arguments` mode already allows through.
- Dashboard UI matches the landing page's visual language (ink `#16181D`,
  ivory `#F4F1EA`, rust accent `#B3401A`, Newsreader headings, IBM Plex
  Sans/Mono) and follows `design/dashboard/` mockups if present. EN/DE/RO
  from the start — i18n keys, no hard-coded UI strings.

## Consequences
- Two Postgres-touching crates now exist conceptually (none yet in the
  gateway, which stays file-based) — `custos-control` is the only consumer
  of `sqlx` in this workspace.
- A commercial crate living in the same Cargo workspace as the Apache-2.0
  gateway means CI and tooling stay shared, but license boundaries must be
  kept explicit per-crate rather than inherited from `[workspace.package]`.
- Login rate limiting starts in-memory (v0 simplification, resets on
  restart) rather than DB-backed; revisit if abuse in the wild needs it to
  survive a restart or work across multiple Control instances.
