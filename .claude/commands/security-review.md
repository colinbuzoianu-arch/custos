---
description: Review uncommitted changes against the security invariants
---
Look at `git diff` (and `git diff --staged`). Check every change against the eight security invariants in CLAUDE.md.
For each problem: file and line, which invariant, a concrete request that would slip through or break, and the fix.
Also flag missing negative tests. If nothing is wrong, say so in one line. Don't edit files unless I ask.
