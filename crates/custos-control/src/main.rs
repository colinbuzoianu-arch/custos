use clap::{Parser, Subcommand};
use custos_control::users::{self, Role};
use custos_control::{AppState, app, config::Config, connect, migrate};
use std::path::PathBuf;
use std::sync::Arc;

/// Env var holding the new admin's password for `create-admin` — never a
/// CLI arg, which would land in shell history. Same convention as
/// CUSTOS_AUDIT_KEY / CUSTOS_SIGNING_KEY in the gateway.
const ADMIN_PASSWORD_ENV: &str = "CUSTOS_CONTROL_ADMIN_PASSWORD";

/// Env var holding the raw Ed25519 signing seed Control uses to sign policy
/// bundles on publish, hex- or base64-encoded. Never held in config, never
/// logged — same convention as the gateway's `CUSTOS_SIGNING_KEY`.
const POLICY_SIGNING_KEY_ENV: &str = "CUSTOS_CONTROL_POLICY_SIGNING_KEY";

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
    /// Create the first admin user for a tenant (creating the tenant if it
    /// doesn't exist yet). Reads the password from CUSTOS_CONTROL_ADMIN_PASSWORD.
    CreateAdmin {
        #[arg(short, long, default_value = "config/custos-control.toml")]
        config: PathBuf,
        #[arg(long)]
        email: String,
        /// Tenant slug, e.g. "acme". Created with this as its name too if
        /// it doesn't exist yet — rename it later if you want something
        /// nicer.
        #[arg(long)]
        tenant: String,
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
            let signing_key_raw = std::env::var(POLICY_SIGNING_KEY_ENV)
                .map_err(|_| anyhow::anyhow!("{POLICY_SIGNING_KEY_ENV} is not set"))?;
            let signing_key_bytes = custos_tokens::decode_key_32(&signing_key_raw)?;
            let state = Arc::new(AppState {
                db,
                login_attempts: Default::default(),
                policy_signing_key: ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes),
                audit_events: tokio::sync::broadcast::channel(
                    custos_control::AUDIT_EVENTS_CAPACITY,
                )
                .0,
            });
            let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
            tracing::info!(listen = %cfg.listen, "custos-control started");
            axum::serve(listener, app(state)).await?;
        }
        Cmd::CreateAdmin {
            config,
            email,
            tenant,
        } => {
            let password = std::env::var(ADMIN_PASSWORD_ENV)
                .map_err(|_| anyhow::anyhow!("{ADMIN_PASSWORD_ENV} is not set"))?;
            let cfg = Config::load(&config)?;
            let db = connect(&cfg.database_url).await?;
            migrate(&db).await?;

            let tenant_id = match users::find_tenant_by_slug(&db, &tenant).await? {
                Some(id) => id,
                None => users::create_tenant(&db, &tenant, &tenant).await?,
            };
            let password_hash = users::hash_password(&password)?;
            users::create_user(&db, tenant_id, &email, &password_hash, Role::Admin).await?;
            println!("OK: admin {email} created for tenant {tenant}");
        }
    }
    Ok(())
}
