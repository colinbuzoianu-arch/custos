# 0008 — Hold and human approval

Date: 2026-09-30 · Status: accepted

## Context
Session 16 makes `Decision::Hold` real: a Cedar policy can mark a call as
needing a human, the gateway has to actually get that human decision from
somewhere, and Custos Control needs a place for a person to make it.

## Decision
- **`@hold`/`@four_eyes` are Cedar annotations**, read via the same API
  `@id` already used (`policy.annotation("hold")`). No schema change —
  annotations aren't schema-validated. `@four_eyes` needs no value;
  presence alone is enough, matching how `@id` treats its own value as
  the only thing that matters.
- **`Decision::Hold` gained a `four_eyes: bool` field.** Breaking change
  to a `custos-core` type used by the gateway, the audit log, and tests —
  mechanical everywhere it showed up (`#[serde(default)]` keeps any
  hypothetical already-serialized `Hold` record, though none exist yet:
  the variant was never actually emitted before this session).
- **The gateway polls Control; Control does not long-poll.** A held call
  asks Control to create an approval, then calls back every
  `approval_poll_interval_secs` (default 2s) asking "what's its status
  now," until it sees `approved`/`rejected` or its own
  `approval_timeout_secs` (default 120s) elapses. Control's answer is
  always immediate — it never holds the HTTP connection open waiting for
  a human. This avoids building server-side wait/notify machinery
  (`tokio::sync::Notify` per pending approval, or `LISTEN`/`NOTIFY`) for
  one feature, consistent with this project's existing preference for
  simple fixed intervals over more complex mechanisms (ADR 0004's sync
  loop, the in-memory rate limiter).
- **Any failure talking to Control blocks immediately — never retries
  until the timeout.** Creating the approval or polling its status can
  fail two ways: Control says no (non-2xx) or Control can't be reached at
  all. Either one blocks the call right then, rather than treating it as
  transient and retrying for the rest of the timeout window. Only a
  genuine `200 {"status": "pending"}` response keeps the polling loop
  going. This means a one-off network blip can block a call that Control
  was about to approve — a deliberate trade favoring predictability
  (`docs/PLAN.md`'s own "Control unreachable → block" reads as unconditional)
  over resilience to a transient error in this one path.
- **The approval client is a separate, read-only copy of the enrollment
  credential**, not shared state with the background sync loop
  (`control_sync::spawn`'s own `ControlState`). Both load the same
  `state_path` independently at startup. `credential` never changes after
  enrollment (only the sync loop's bundle ETag and shipping checkpoint
  do), so the two copies can never disagree — this avoids threading a
  shared, mutex-protected handle through both the background loop and the
  per-request hold path for no behavioral benefit.
- **Four-eyes is enforced by name, at resolution time, in Control.** The
  approval carries the gateway's own `ToolCall.agent` string; `resolve()`
  looks that name up in the `agents` table for `owner_user_id` and
  refuses (writing nothing) if the resolving user is that owner. The
  resolving `UPDATE` itself re-checks `status = 'pending'` in its `WHERE`
  clause, so two approvers racing to resolve the same approval can't both
  succeed.
- **Every step writes to the gateway's own audit log**, not a separate
  approvals-specific audit trail: the initial `Hold` is written (and
  flushed) before polling starts, and the final `Allow`/`Block` once
  resolved — before that outcome is acted on, per invariant 3. Two audit
  records for one call, not a new logging mechanism.

## Consequences
- A gateway with no `[control]` section, or one whose enrollment state
  fails to load, cannot resolve any `@hold` — every one fails closed to
  `Block`, unconditionally. This was already true in spirit (no Control,
  no way to ask a human) but is now the actual enforced behavior rather
  than a hypothetical.
- Control's `approvals` table and its four endpoints
  (`POST/GET /api/gateways/approvals[/{id}]` for the gateway,
  `GET /api/approvals` + `POST /api/approvals/{id}/approve|reject` for a
  person) are new surface with no dashboard yet — the Approvals page is
  the follow-up to this ADR's commit, not included in it.
- `four_eyes` matches agents by name, not by a stable id — if an agent is
  renamed on the Control side without the gateway's config catching up,
  the owner lookup silently finds nothing and the check can't fire. Not
  addressed here; worth revisiting if agent renaming becomes a real
  workflow.
