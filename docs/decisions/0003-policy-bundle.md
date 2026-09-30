# 0003 — Policy bundle format and signing

Date: 2026-09-30 · Status: accepted

## Context
Session 11 adds versioned policy sets to Control. Publishing a version must
hand a gateway something it can verify came from Control unmodified: the
policy text, the schema it was validated against, and the list of agents
(and their token hashes) it applies to. Session 12 (gateway enrolment/sync)
will be the consumer; this ADR pins the shape now so that work has a fixed
target.

## Decision
- **One signed bundle per publish**, built fresh from that version's stored
  text and the tenant's *currently* active agents — not a snapshot taken at
  save time, since agents can be added/disabled between saving a draft and
  publishing it.
- **Wire format is "sign the exact bytes, keep them verbatim."** The
  published artifact is `{ bundle_json: string, signature: string }`, where
  `bundle_json` is the JSON text that was actually signed and `signature` is
  its Ed25519 signature, base64url-encoded. Verification never re-serializes
  the bundle to check the signature — `serde_json::Value` doesn't
  necessarily produce the same bytes on a second encoding (object key order
  isn't preserved by default), so re-encoding before verifying could make a
  genuine bundle look tampered, or worse, mask a real change if the
  re-encoding happened to coincide. Keeping the signed string itself avoids
  the whole class of bug.
- **Signing key**: Control has one Ed25519 signing key, loaded at startup
  from `CUSTOS_CONTROL_POLICY_SIGNING_KEY` (hex or base64, 32-byte seed) —
  same convention as the gateway's `CUSTOS_SIGNING_KEY` (ADR-adjacent,
  session 8), never written to config or logged. No rotation support yet
  (single key, no key id in the bundle) — add both together when Control
  needs to rotate its own key, likely alongside session 12's gateway-side
  key pinning.
- **Publish never re-validates.** A version can only be published if it was
  already marked valid when saved; publish itself does not re-run schema
  validation. This is deliberate: if the schema changes after a version was
  saved and validated, that version's validity as recorded reflects what was
  true when someone reviewed and saved it, not a silent re-check that could
  reject something already approved.
- **Diff is text, not structured.** `GET /policies/diff` returns a unified
  diff (via the `similar` crate) of the two versions' Cedar source. Good
  enough for a human reviewing a change in session 15's dashboard; nothing
  here needs a semantic policy diff yet.

## Consequences
- Adds `similar` as a new dependency (text diffing; no existing crate in the
  workspace did this).
- `custos-policy` gained two small public, string-based entry points
  (`parse_schema_str`, `validate_source`) so Control can validate Cedar
  source stored in a database column without writing it to a temp file
  first — the existing API was file/directory-shaped.
- A gateway (session 12) will need to hold Control's *verifying* key the
  same way it already holds agent-token verifying keys, to check a bundle
  before applying it.
