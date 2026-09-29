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
    },
    /// Print the SHA-256 of an agent token, for the config file.
    HashToken { token: String },
    /// Check that an audit log's hash chain is intact.
    VerifyAudit { path: PathBuf },
    /// Parse and validate every `*.cedar` file in a directory, without
    /// starting the gateway. Exit 0 if all are valid, 1 otherwise.
    CheckPolicy { dir: PathBuf },
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
        Cmd::Run { config } => {
            let cfg = Config::load(&config)?;
            let state = Arc::new(AppState::from_config(&cfg)?);
            let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
            tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, agents = cfg.agents.len(), "custos gateway started");
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
    }
    Ok(())
}
