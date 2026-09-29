use clap::{Parser, Subcommand};
use custos_gateway::{AppState, app, config::Config, hash_token};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "custos", version, about = "Runtime control for AI agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the gateway.
    Run {
        #[arg(short, long, default_value = "config/custos.toml")]
        config: PathBuf,
        /// Also reload the policy set whenever a file under `policy_dir`
        /// changes (debounced ~500ms). SIGHUP always reloads on Unix,
        /// with or without this flag.
        #[arg(long)]
        watch_policies: bool,
    },
    /// Print the SHA-256 of an agent token, for the config file.
    HashToken { token: String },
    /// Check that an audit log's hash chain is intact.
    VerifyAudit { path: PathBuf },
    /// Parse and validate every `*.cedar` file in a directory, without
    /// starting the gateway. Exit 0 if all are valid, 1 otherwise.
    CheckPolicy { dir: PathBuf },
    /// Check that a running gateway (started with the same config) is
    /// answering `/healthz`. Exit 0 if it is, 1 otherwise. Distroless images
    /// have no shell or curl, so this is what the container HEALTHCHECK
    /// runs instead.
    Healthcheck {
        #[arg(short, long, default_value = "config/custos.toml")]
        config: PathBuf,
    },
    /// Issue a short-lived, Ed25519-signed agent token (for `auth =
    /// "signed"`). Reads the signing key from CUSTOS_SIGNING_KEY (hex or
    /// base64, 32 bytes) - generate one the same way as CUSTOS_AUDIT_KEY,
    /// e.g. `openssl rand -hex 32`. Never held in config, never logged.
    IssueToken {
        #[arg(long)]
        agent: String,
        /// e.g. `30m`, `1h`, `2d`.
        #[arg(long, value_parser = parse_ttl_secs)]
        ttl: i64,
        /// Which trusted key signed this token — must match a `key_id` in
        /// the gateway's `[[signing_keys]]`.
        #[arg(long)]
        key_id: String,
    },
}

/// Parses a duration like `30m`, `1h`, `2d` into seconds. Hand-rolled rather
/// than pulling in a duration-parsing crate for one CLI flag.
fn parse_ttl_secs(s: &str) -> Result<i64, String> {
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| format!("{s:?}: expected a number followed by s/m/h/d, e.g. 1h"))?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("{s:?}: unit must be one of s, m, h, d")),
    };
    Ok(n * secs)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,custos_gateway=info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Run {
            config,
            watch_policies,
        } => {
            let cfg = Config::load(&config)?;
            let state = Arc::new(AppState::from_config(&cfg)?);
            // Held for the process lifetime: dropping it would stop the file
            // watcher. `None` when --watch-policies wasn't given.
            let _policy_watcher =
                custos_gateway::spawn_policy_reload_triggers(state.clone(), watch_policies)?;
            custos_gateway::spawn_session_expiry_sweep(state.clone());
            let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
            tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, agents = cfg.agents.len(), watch_policies, "custos gateway started");
            axum::serve(listener, app(state)).await?;
        }
        Cmd::HashToken { token } => println!("{}", hash_token(&token)),
        Cmd::VerifyAudit { path } => match custos_audit::verify(&path) {
            Ok((n, _)) => println!("OK: {n} records, chain intact"),
            Err(e) => {
                eprintln!("FAILED: {e}");
                std::process::exit(1);
            }
        },
        Cmd::CheckPolicy { dir } => {
            let reports = match custos_policy::check_dir(&dir) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("FAILED: {e}");
                    std::process::exit(1);
                }
            };
            let mut ok = true;
            let mut total_policies = 0;
            for r in &reports {
                if r.is_valid() {
                    total_policies += r.policy_count;
                    println!("OK: {} ({} policies)", r.path.display(), r.policy_count);
                    for id in &r.missing_id {
                        println!("  warning: {} has no @id ({id})", r.path.display());
                    }
                } else {
                    ok = false;
                    for e in &r.errors {
                        eprintln!("{}: {e}", r.path.display());
                    }
                }
            }
            if ok {
                println!("OK: {total_policies} policies in {} file(s)", reports.len());
            } else {
                std::process::exit(1);
            }
        }
        Cmd::Healthcheck { config } => {
            let cfg = match Config::load(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("FAILED: {e}");
                    std::process::exit(1);
                }
            };
            // Always loopback: this only ever runs inside the same
            // container/host as the gateway it's checking, regardless of
            // what address the gateway itself is configured to bind.
            let url = format!("http://127.0.0.1:{}/healthz", cfg.listen.port());
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("FAILED: {e}");
                    std::process::exit(1);
                }
            };
            match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => println!("OK: {url}"),
                Ok(r) => {
                    eprintln!("FAILED: {url} returned {}", r.status());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("FAILED: {url}: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::IssueToken { agent, ttl, key_id } => {
            let raw = match std::env::var(custos_gateway::config::SIGNING_KEY_ENV) {
                Ok(v) => v,
                Err(_) => {
                    eprintln!(
                        "FAILED: {} is not set",
                        custos_gateway::config::SIGNING_KEY_ENV
                    );
                    std::process::exit(1);
                }
            };
            let seed = match custos_tokens::decode_key_32(&raw) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("FAILED: {e}");
                    std::process::exit(1);
                }
            };
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let token = custos_tokens::issue(
                &signing_key,
                &agent,
                custos_gateway::now_unix(),
                ttl,
                &key_id,
            );
            println!("{token}");
        }
    }
    Ok(())
}
