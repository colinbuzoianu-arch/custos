---
description: Run fmt, clippy and tests, and fix what fails
---
Run in order: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
If something fails, fix the cause (never silence a lint or weaken a test to pass) and run again. Report the final state in three lines.
