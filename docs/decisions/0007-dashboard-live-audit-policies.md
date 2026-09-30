# 0007 — Live decisions, audit export, and the policy editor

Date: 2026-09-30 · Status: accepted

## Context
Session 15 adds three dashboard pages on top of session 14's shell. All
three consume APIs that already existed (audit search/stream from session
13, policy versioning/publish/diff from session 11) except one small gap
found while building the editor.

## Decision
- **A new `POST /api/policies/validate`.** "Validate as you type" cannot
  reuse `save_draft` — that inserts a new `policy_versions` row on every
  call, so calling it per keystroke would flood the table with garbage
  drafts. `policies::save_draft`'s validation step was factored out into a
  pure, DB-free `policies::validate()` and exposed on its own endpoint.
- **Cedar syntax highlighting via a parameterized C-like mode, not a real
  grammar.** No CodeMirror language exists for Cedar. `@codemirror/legacy-modes`'s
  `clike()` builds a `StreamParser` from a configurable skeleton
  (keywords, atoms, `::`-namespaced identifiers, strings, `//` comments)
  that Cedar's actual syntax is close enough to for reasonable
  highlighting, without writing and maintaining a full parser for one
  editor. `@uiw/react-codemirror` is the CodeMirror 6 React wrapper — it
  avoids hand-wiring `EditorView`/`EditorState` lifecycle inside React
  ourselves.
- **Audit export walks the existing paginated search API, capped, not a
  new bulk-export endpoint.** There's no server-side "export everything
  matching these filters" capability, and building one wasn't obviously
  worth it yet. Export means: call `GET /api/audit` repeatedly with the
  current filters and each page's cursor, accumulate, stop at 50 pages of
  200 (10,000 records) or when there's no next cursor, then build a CSV or
  JSON file client-side and trigger a browser download. This is a
  deliberate cap, not a claim that results never exceed it — if that
  becomes a real limitation, the fix is a real export endpoint, not a
  higher cap.
- **The live decisions page is a thin client over the SSE stream, not a
  second source of truth.** It holds only the last 200 events in memory,
  filters them client-side (agent/tool/verdict), and drops anything
  received while paused rather than buffering it — the underlying
  `audit_records` table (via the search page) is where a real history
  lookup belongs; this page is for watching what's happening right now.
- **The policy editor page is gated to the `admin` role client-side**,
  matching what every policy endpoint already enforces server-side
  (`AdminUser`) — every one of them, including a plain list, was already
  admin-only before this session, so hiding the whole page for non-admins
  is just not showing controls nobody could use anyway, not a new
  authorization decision.

## Consequences
- New frontend dependencies: `@uiw/react-codemirror`, `@codemirror/legacy-modes`,
  `@codemirror/language`.
- The production bundle crossed Vite's 500KB chunk-size warning threshold
  (CodeMirror's language machinery is the bulk of it). Not addressed here
  — code-splitting the policy editor behind a dynamic `import()` so it's
  not in the initial bundle would be the fix, worth doing once the
  dashboard has enough pages that initial load time actually matters.
- Same standing caveat as ADR 0006: none of this was checked in an actual
  browser — build (`tsc -b && vite build`), lint (`oxlint`), and manual
  `curl` checks of the dev server's routes were the only verification
  available in this environment.
