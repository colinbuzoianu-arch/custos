# 0006 — Dashboard: API prefix, stack choices, and what's still open

Date: 2026-09-30 · Status: accepted

## Context
Session 14 adds the first Custos Control UI. ADR 0002 already decided
*what* it is (Vite + React + TypeScript, embedded via `rust-embed`, EN/DE/RO
from the start); this ADR covers what came up while actually building it.

## Decision
- **Every existing Control route moved under `/api`.** Before the
  dashboard existed, `/agents`, `/overview`, `/policies`, etc. were
  unprefixed — fine when the only client was `curl` or a gateway. Once a
  single-page app is served from the same origin, its own client-side
  route `/agents` (a *page*) and the API's `/agents` (data) would collide.
  `/healthz` stays unprefixed (infra health checks expect it at a fixed,
  conventional path). This touched every route in `lib.rs`, the three
  gateway-side call sites in `control_sync.rs`, and every literal path in
  `tests/control.rs` — mechanical, not a design change to any individual
  endpoint.
- **A new `GET /api/me`** returns the caller's role and a fresh CSRF token.
  Without it, refreshing the dashboard page would look logged-out even
  with a perfectly valid session cookie (the cookie is HttpOnly and
  survives a refresh; anything the page only held in memory — role, CSRF
  token — doesn't). `CurrentUser` gained a `csrf_token()` accessor to
  support this.
- **`react-router` for routing, `react-i18next` for i18n.** Both are the
  standard choice for a React SPA; nothing project-specific pushed toward
  an alternative.
- **Auth state lives in a React context backed by `/api/me`**, not
  `localStorage`. On load, the dashboard always asks Control "am I logged
  in" rather than trusting anything cached client-side — the session
  cookie is the actual source of truth either way.
- **Fonts are not self-hosted yet.** The palette (ink/ivory/rust) from ADR
  0002 is in `theme.css`; Newsreader/IBM Plex Sans/Mono are named in the
  font stacks but fall back to system fonts until actual font files are
  added — no `design/dashboard/` mockups exist yet to source them from,
  and pulling live from Google Fonts would mean an external network call
  every page load for a self-hosted product (ADR 0002's "audit data never
  leaves the network" reasoning applies to more than just audit data).

## Consequences / open items
- **Not embedded into the `custos-control` binary yet.** `rust-embed`
  needs `dashboard/dist/` to exist at Rust compile time; requiring every
  contributor to run `npm run build` before `cargo build` would break the
  existing `cargo test --workspace` workflow for anyone not touching the
  dashboard. Deferred until there's a real build/CI step to sequence the
  two — for now, `npm run dev`'s proxy (`vite.config.ts`) is the only
  supported way to run the dashboard against Control.
- **Agents page is read-only** (list only). Create, disable, and issue
  token — including the "shown once" token flow — are the rest of session
  14, not done here.
- **No browser was used to verify this work.** Build (`tsc -b && vite
  build`), lint (`oxlint`), and the dev server's proxy behavior were all
  checked from the command line; visible-focus, keyboard navigation, and
  actual contrast were not checked in a real browser, which CLAUDE.md's
  own rule for UI work calls for. Flagged explicitly rather than claimed.
