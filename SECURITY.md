# Security policy

Custos is a security product: a bug that lets a call through matters more
than almost anything else that could go wrong here. If you've found one,
please tell us privately before it's public.

## Reporting a vulnerability

Email **security@worldlegalservice.com** with:

- what you found and why it matters (which security invariant it breaks —
  see `CLAUDE.md` in this repo for the list Custos is meant to hold to),
- steps to reproduce, or a minimal example,
- the version or commit you tested against.

Please don't open a public GitHub issue for a suspected vulnerability.

We aim to acknowledge reports within **5 business days** and to follow up
with an assessment and, where confirmed, a fix timeline. We'll credit you in
the release notes unless you'd rather stay anonymous.

## Supported versions

Custos is pre-1.0. Only the latest tagged release is supported; please
upgrade before reporting an issue that a newer release might already fix.

## Scope

In scope: the gateway (`crates/custos-gateway`), the policy engine
(`crates/custos-policy`), and the audit log (`crates/custos-audit`) in this
repository. Out of scope: the MCP servers Custos proxies to, and
infrastructure you run it on.
