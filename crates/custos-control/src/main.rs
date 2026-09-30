use clap::{Parser, Subcommand};
use custos_control::{AppState, app, config::Config, connect, migrate};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "custos-control", version, about = "Custos Control")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start Control.
    Run {
        #[arg(short, long, default_value = "config/custos-control.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,custos_control=info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Run { config } => {
            let cfg = Config::load(&config)?;
            let db = connect(&cfg.database_url).await?;
            migrate(&db).await?;
            let state = Arc::new(AppState { db });
            let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
            tracing::info!(listen = %cfg.listen, "custos-control started");
            axum::serve(listener, app(state)).await?;
        }
    }
    Ok(())
}
