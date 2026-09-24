# Custos

Runtime control for AI agents. Custos sits between your agents and the tools
they call. Every call is identified, checked against policy, recorded in a
tamper-evident log, and then allowed or blocked, before it happens.

Status: early development. Not for production use yet.

## Try it

```bash
cargo test --workspace
cp config/custos.example.toml config/custos.toml
cargo run -p custos-gateway -- hash-token my-secret-agent-token   # paste into custos.toml
cargo run -p custos-gateway -- run --config config/custos.toml
```

Point an MCP client at `http://127.0.0.1:8787/mcp` with
`Authorization: Bearer my-secret-agent-token`.

Docs: [architecture](docs/ARCHITECTURE.md) · [plan](docs/PLAN.md)

Gateway licensed under Apache-2.0. © Verumsell SRL.
