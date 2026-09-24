# Custos — notes for Claude Code

Custos is a runtime firewall for AI agents. It sits between agents and the
tools they call (MCP servers first), identifies each agent, checks every tool
call against Cedar policy, writes a tamper-evident audit record, and only then
forwards or blocks the call. Product of Verumsell SRL, published under World
Legal Service. Gateway is open source (Apache-2.0); the control plane will be
commercial.

## Repo map

- `crates/custos-core` — shared types: `AgentId`, `ToolCall`, `Decision`. Keep it tiny.
- `crates/custos-policy` — Cedar wrapper. Model: principal `Agent::"id"`, action `Action::"call_tool"`, resource `Tool::"name"`.
- `crates/custos-audit` — append-only JSON Lines log, SHA-256 hash chain, `verify()`.
- `crates/custos-gateway` — axum HTTP proxy for MCP streamable HTTP + the `custos` binary.
- `policies/` — example Cedar policies. `config/` — example config.
- `docs/PLAN.md` — the build plan with checkboxes. **This is the source of truth for what to do next.**
- `docs/ARCHITECTURE.md` — how a request flows. `docs/decisions/` — architecture decision records.

## Commands

```bash
cargo test --workspace                              # all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run -p custos-gateway -- run --config config/custos.toml
cargo run -p custos-gateway -- hash-token <token>
cargo run -p custos-gateway -- verify-audit data/audit.jsonl
```

A task is done only when all three of test, clippy and fmt pass.

## Security invariants — never break these

This is a security product. A bug that lets a call through is worse than a
bug that blocks one. If a change would weaken any line below, stop and ask.

1. **Fail closed.** Anything the gateway cannot parse, authenticate, evaluate
   or audit is rejected. No "allow on error" paths.
2. **Default deny.** A tool call is allowed only if a Cedar `permit` matches and no `forbid` does.
3. **Audit before acting.** The decision is written (and flushed) before the call is forwarded. If the write fails, block.
4. **Never forward the agent's credentials.** Only headers on the allow-list in
   `FORWARD_REQUEST_HEADERS` go upstream. Upstream credentials come from config.
5. **Never store plain tokens.** Agent tokens are stored and compared as SHA-256 hashes.
6. **Treat everything as hostile input:** tool names, arguments, JSON-RPC ids, upstream responses, config values. Build Cedar uids through `uid()` (JSON-escaped), never by string formatting.
7. **No `unsafe`, no `unwrap()`/`expect()` in non-test code.** Handle errors explicitly.
8. **Every security behaviour has a test that proves it**, including the negative case (blocked call never reaches upstream).

## Conventions

- Rust 2024 edition, stable toolchain. Libraries use `thiserror`; the binary uses `anyhow`.
- Logging with `tracing` (structured fields), never `println!` outside the CLI output.
- Don't add a dependency without saying why in the same message; prefer well-maintained crates.
- Keep changes small: one task from `docs/PLAN.md` per branch or commit. Tick its box when done.
- Public functions get a one-line doc comment saying what they guarantee.
- Architecture changes get a short ADR in `docs/decisions/`.

## Working with Colin

- Colin is the founder and learned to code by building with Claude; he is new to Rust.
  When you introduce a Rust concept he hasn't seen in this repo yet (lifetimes,
  traits, `Arc`/`Mutex`, async, `?`), explain it in two or three plain sentences.
- For anything touching more than two files, first show a short plan and wait for a go.
- After finishing, summarise what changed, what was tested and what is still open. No long recaps.
- Business context: target buyers are European (DACH, Romania) companies running AI agents;
  EU AI Act, NIS2 and GDPR matter. User-facing text will exist in EN, DE and RO.
