# 0010 — Synced agent tokens actually authenticate

Date: 2026-09-30 · Status: accepted

## Context
Found during session 18's release review: a signed policy bundle (session
12) has always carried `agents: Vec<BundleAgent>` — each active agent's
name and token hash — but the gateway only ever applied the bundle's
*policy* and *schema*. `AppState.agents` (what `authenticate()` actually
checks for `auth = "static"`) was never updated from a sync. Creating an
agent and issuing it a token in Control had no effect on any gateway
syncing with it; an operator still had to hand-copy the hash into that
gateway's local config for it to work. Not a hole that lets anything
through — the opposite, a Control-issued token silently didn't work — but
it defeated a chunk of what "gateway syncs with Control" is supposed to
mean.

## Decision
- **A second, separate agent set** (`AppState::synced_agents`, a
  `Mutex<HashMap<String, AgentId>>`) sits alongside the existing
  config-defined `agents` map. `authenticate()` checks the config map
  first, then this one — config-defined agents can never be shadowed by a
  sync.
- **Replaced wholesale on every successful sync, never merged.**
  `AppState::apply_synced_agents` throws away the previous contents and
  rebuilds from exactly what the current bundle lists. A bundle is already
  a full snapshot (ADR 0003) — if an agent's token is rotated or the agent
  is disabled, the old hash simply won't be in the next bundle, so merging
  would leave stale, still-valid entries behind indefinitely. Replacing
  means a revocation takes effect the moment the next sync succeeds.
- **Applied right after a successful policy reload, from the same
  verified bundle** — not fetched or checked separately. The policy and
  the agents allowed to call under it come from one signed object; there's
  no reason for them to ever be out of sync with each other from two
  different fetches.

## Consequences
- A gateway that syncs with Control can now genuinely show: create an
  agent, issue it a token, the gateway picks it up on its next poll, no
  manual config edit. This is what the session 18 end-to-end demo relies
  on.
- `BundleAgent` still carries no owner information, so an agent that only
  exists via sync (never locally configured) has no owner in this
  gateway's audit records (`owner: null`) — unchanged from before, since
  such an agent couldn't authenticate at all previously. Worth revisiting
  if owner attribution for synced-only agents becomes something a
  customer needs.
