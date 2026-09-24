---
description: Pick up the next open task from docs/PLAN.md
---
Read `docs/PLAN.md` and `CLAUDE.md`. Find the first unchecked task (`- [ ]`).

1. Say which task it is and give a short plan: files to touch, tests to add, any new dependency and why.
2. Wait for my go before editing more than two files.
3. Implement it with tests, including the negative/blocked case where relevant.
4. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Fix until all pass.
5. Tick the box in `docs/PLAN.md` and summarise: what changed, what was tested, what is still open. Explain any Rust concept that is new in this repo.
