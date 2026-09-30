# 0004 — Gateway enrollment and policy sync

Date: 2026-09-30 · Status: accepted

## Context
Session 12 connects a gateway to Control: enrollment, pulling the signed
policy bundle from ADR 0003, and a heartbeat. This has to hold even when
Control is unreachable or sends something bad — a gateway is a security
boundary, so "can't reach Control" must never mean "stop enforcing policy."

## Decision
- **A gateway authenticates to Control the way an agent authenticates to
  the gateway, roles reversed.** It holds a credential (two concatenated
  UUID v4s, same recipe as an agent token); Control stores only its
  SHA-256 hash (`gateways.credential_sha256`). The credential itself lives
  in plaintext in a small local state file (`control-state.json` by
  default) that `custos enroll` writes — this is the gateway's own secret
  to present, not something it verifies, so it's the same category as
  `upstream_authorization` in config, not the agent tokens the gateway must
  never store unhashed.
- **Enrollment is a one-time token, not a login.** An admin issues one in
  Control (`POST /gateways/enroll-tokens`, expires in 1h, single-use); the
  operator pastes it into `custos enroll --control <url> --token <token>`,
  which exchanges it once for the permanent credential and Control's
  pinned Ed25519 public key.
- **Sync is entirely optional and additive.** No `[control]` section in a
  gateway's config means zero outbound calls to anything and identical
  behavior to every session before this one. A `[control]` section with no
  enrollment file yet logs an error and disables sync, rather than
  refusing to start — an operational gap, not a security one.
- **Applying a bundle never risks the last-good policy.** The sequence is
  always: verify the signature → validate the policy+schema text with
  `custos_policy::validate_source` (no disk writes yet) → only then
  overwrite the one fixed file pair (`control-bundle.cedar`,
  `custos.cedarschema`) in `policy_dir` → `PolicyStore::reload()`. Any
  failure at any step logs and returns, touching nothing. A gateway that
  never reaches Control again keeps enforcing whatever's already on disk,
  including across a restart — there's no separate "last good" cache to
  keep in sync, `policy_dir` already *is* it.
- **`policy_dir` should hold only the synced file pair once `[control]` is
  set.** `PolicyStore` concatenates every `*.cedar` file it finds; a
  hand-authored file left in the same directory would get merged in
  alongside the bundle, which Control never validated together. Not
  enforced in code yet — worth a `check-policy`-time warning later if this
  trips someone up in practice.
- **ETag is the bundle's version number**, not a content hash — Control
  already has a per-tenant, monotonic `policy_versions.version`, and a
  bundle is immutable once published (ADR 0003), so the version alone is a
  valid cache key.
- **Heartbeat counts are cumulative since the gateway process started**,
  not since the last heartbeat — simpler to reason about (no risk of a
  missed heartbeat silently dropping counts) at the cost of Control having
  to diff two heartbeats itself if it ever wants a rate.

## Consequences
- New gateway dependencies: `thiserror` (for `ControlError` — the crate
  already used `anyhow` at the binary level but had no library-style error
  enum yet), `uuid`, `time` (both already used transitively via
  `custos-policy::bundle`, now direct so the gateway can construct/read
  `ControlState` and test against `PolicyBundle` itself).
- `time`'s `parsing` feature is now enabled workspace-wide (it was only
  `formatting` + `serde` before) — needed for `serde(with =
  "time::serde::rfc3339")` to *deserialize*, which `PolicyBundle` needs
  and `custos-control`'s own types hadn't required yet (they only ever
  serialized).
