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
    }
    Ok(())
}
