# 0009 — Evidence export: PDF library, signing, and the compliance mapping

Date: 2026-09-30 · Status: accepted

## Context
Session 17 adds an evidence pack for a time range: a signed JSON bundle of
the underlying records, plus a human-readable PDF report in EN/DE/RO. This
is the first PDF-generation capability in the workspace.

## Decision
- **`genpdf`** (pure Rust, built on `printpdf`) generates the PDF. No
  external binary (no headless Chromium, no `wkhtmltopdf`) — consistent
  with ADR 0002's self-hosted, no-outbound-dependency posture, and it
  renders straight into an in-memory buffer (`doc.render(&mut Vec<u8>)`),
  so the HTTP handler never touches the filesystem.
- **The font (PT Sans) is vendored and embedded at compile time**
  (`include_bytes!`), not loaded from disk at runtime. It's OFL-1.1
  licensed (`crates/custos-control/assets/fonts/OFL.txt`) and was chosen
  over DejaVu/Liberation/current Roboto because those are now
  variable-font-only in their canonical sources — `genpdf`'s loader wants
  four separate static files (Regular/Bold/Italic/BoldItalic) — and PT
  Sans covers the Latin Extended-A glyphs German and Romanian need (ü, ß,
  ă, â, î, ș, ț), verified by a test that actually renders a PDF in all
  three languages and checks the output is well-formed.
- **The evidence bundle is signed with the same Ed25519 key that already
  signs policy bundles** (`AppState.policy_signing_key`), not a second
  key. Same wire-format reasoning as `custos_policy::bundle::SignedBundle`
  (session 11): the signed JSON string travels verbatim alongside its
  signature, never re-serialized to verify, since re-encoding a parsed
  value isn't guaranteed to reproduce the same bytes.
- **Two endpoints, one data-gathering function.** `GET /api/evidence.json`
  and `GET /api/evidence.pdf` both call `evidence::gather`, which is
  time-ranged for decisions and resolved approvals, but not for the agent
  inventory, gateway health, or policy history — those are current-state
  or full-history data where filtering to the window would just hide
  facts a reviewer needs (e.g. "which policy governed this period" can
  predate the window's start).
- **The compliance mapping is a labeled, disclaimed appendix**, not woven
  into the data sections, and its wording says "supports" rather than
  "satisfies" or "complies with" throughout. It names specific provisions
  (EU AI Act Art. 12 & 14, NIS2 Art. 21(2)(a)/(e), GDPR Art. 5(1)(c)/(f))
  because a vague mapping would be less useful to a customer's own counsel
  than a precise, checkable one — but precision here creates real
  correctness risk if a citation is wrong. **This wording has not had
  legal review.** It's drafted content, not verified legal claims,
  flagged explicitly to Colin for review before any customer-facing use.
- **Only findings, never raw arguments**, appear in the report — the
  evidence bundle draws on the same `audit_records`/`approvals` data the
  rest of Control already stores, which itself only ever holds raw
  arguments if the gateway's own `audit_arguments` mode is `full`. The
  report doesn't add or relax that guarantee, it just inherits it.

## Consequences
- New dependency: `genpdf` (and its own dependency, `printpdf`) — the
  first PDF-generation capability in the workspace, isolated to
  `custos-control::evidence::pdf`.
- New binary asset: four TTF files plus their license text, adding
  roughly 1.7 MB to the crate's source tree and to every build of the
  `custos-control` binary (embedded, not optional).
- No dashboard page yet for triggering an export — both endpoints exist
  and are tested, but there's no UI button. Worth adding once there's a
  natural home for it (an "Evidence" page, or a button on Overview).
