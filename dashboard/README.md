# Custos dashboard

The Custos Control web UI. Vite + React + TypeScript, `react-router` for
routing, `react-i18next` for EN/DE/RO. See `docs/decisions/0006-dashboard.md`
for why it's built this way.

## Development

Run a real Control instance first (needs Postgres — see the root
`README.md`/`docs/DEMO.md`):

```bash
cargo run -p custos-control -- run --config config/custos-control.toml
```

Then, in this directory:

```bash
npm install
npm run dev
```

Vite serves the dashboard on its own port and proxies every `/api/*`
request to Control (`vite.config.ts`), so the browser only ever talks to
one origin during development, the same as in production.

## Building

```bash
npm run build
```

Type-checks (`tsc -b`) then produces `dist/`. Not embedded into the
`custos-control` binary yet — see the open item in
`docs/decisions/0006-dashboard.md`.
