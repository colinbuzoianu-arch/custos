# syntax=docker/dockerfile:1

# Matches rust-version in Cargo.toml, and bookworm to match the distroless
# base below — the final binary is dynamically linked against glibc, so the
# builder's glibc must be compatible with the runtime image's.
FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p custos-gateway

# Pre-create the audit log directory with the runtime user's ownership.
# Distroless has no shell, so this can't be done after the fact - and a
# Docker volume mounted over this path inherits this ownership on first
# creation.
RUN mkdir -p /data-stage/var/lib/custos

# distroless/cc-debian12:nonroot: glibc + libgcc (no shell, no package
# manager), already runs as a non-root user by default.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/custos /usr/local/bin/custos
COPY --from=builder --chown=nonroot:nonroot /data-stage/var/lib/custos /var/lib/custos

USER nonroot
EXPOSE 8787

# Exec form: runs without a shell, which this image doesn't have.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/custos", "healthcheck", "--config", "/etc/custos/custos.toml"]

ENTRYPOINT ["/usr/local/bin/custos"]
CMD ["run", "--config", "/etc/custos/custos.toml"]
