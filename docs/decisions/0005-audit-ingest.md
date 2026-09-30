# 0005 — Audit ingestion: schema tolerance, chain flagging, search, live stream

Date: 2026-09-30 · Status: accepted

## Context
Session 13 gets a gateway's local audit log into Control: shipped in
batches, checked for continuity, searchable, and streamed live. The
gateway's audit log already has four record schemas (v1–v4) with a
versioned SHA-256 hash chain (`custos-audit`); Control has to accept all
of them without becoming a fifth place that hash logic has to be kept in
sync.

## Decision
- **Ingestion is schema-tolerant, not strongly typed.** `POST
  /gateways/audit/batch` takes each line as a raw `serde_json::Value` and
  stores it verbatim in a `jsonb` column. Search-relevant fields (agent,
  tool, verdict, ts, policy_version) are extracted best-effort into
  nullable columns; a record missing all of them is still stored, only one
  with no usable `seq` is skipped (seq is what makes ingestion idempotent,
  so there's nothing safe to do with one that lacks it).
- **Chain checking flags, it doesn't re-verify.** Control compares each
  newly ingested record's `(seq, prev_hash)` against the last one it
  ingested for that gateway and marks `gateways.chain_status` as `ok` /
  `gap` / `broken`, with a reason in `chain_issue`. It does **not**
  recompute the record's SHA-256 hash — that would mean porting
  `custos-audit`'s per-version hashing (`Hashed`, `HashedV3`, ...) into
  Control and keeping the two in lockstep forever. A future version could
  add real re-verification as a stronger check; flagging is the
  session-13 scope.
- **A flag never self-clears.** Once a gateway's chain is marked `gap` or
  `broken`, a later well-linked record does not quietly reset it back to
  `ok`. A real discontinuity stays visible until an operator looks at it.
- **Idempotency key is `(gateway_id, seq)`**, enforced with a unique
  constraint and `ON CONFLICT DO NOTHING` — resending a batch after a
  retry is a no-op, not a duplicate row or an error.
- **Search pagination keys on `(ingested_at, id)`, not `(ts, id)`.**
  `ts` (the event's own timestamp, from the gateway) can be null for a
  malformed record; `ingested_at` (server-assigned, never null) can't. A
  keyset cursor needs a total order that's always present. Time-range
  filtering (`from`/`to`) still filters on `ts`, since that's what a
  search actually means by "when did this happen" — a record with no `ts`
  simply won't match a bounded range query, which is correct.
- **The cursor is opaque** (base64 of `"<ingested_at>,<id>"`), not a raw
  offset — callers pass it back verbatim, nothing about its shape is a
  contract.
- **The live stream is one in-process `tokio::sync::broadcast` channel**,
  not a database-backed pub/sub or an external message queue. Every
  ingested batch broadcasts its newly inserted records; every `/audit/stream`
  connection subscribes and filters to its own tenant. This is
  single-instance only — if Control ever runs as more than one process,
  the stream would need to move to something shared (e.g. `LISTEN`/`NOTIFY`
  or a real queue). Not a concern yet (ADR 0002: self-hosted, one Control
  instance per customer).

## Consequences
- New Control dependencies: `base64` (cursor encoding — already used
  elsewhere in the workspace, just not previously a direct dependency of
  this crate) and `futures-util` (already a workspace dependency, needed
  here for `Stream`/`stream::unfold` to build the SSE body).
- `gateways` gained four columns (`last_ingested_seq`,
  `last_ingested_hash`, `chain_status`, `chain_issue`) rather than a
  separate one-row-per-gateway tracking table — there's exactly one chain
  per gateway, so a separate table would just be a 1:1 join for no benefit.
- A lagging SSE subscriber (slower than the broadcast channel's capacity)
  skips ahead rather than disconnecting — it can miss events, which is
  the right tradeoff for a live dashboard feed backed by the searchable
  table underneath: nothing is ever lost, only possibly not shown live.
