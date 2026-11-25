mod config;
mod engine;
mod identity;
mod scan;
mod state;
mod upgrade;
mod web;
mod wire;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use config::{Config, Role};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "One-way, authenticated folder sync that preserves replica-only files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        root: PathBuf,
        #[arg(
            long,
            help = "Replica listener IP:port; optional for source and editable in Web"
        )]
        addr: Option<String>,
        #[arg(long, help = "Source web listener; default 0.0.0.0:8787")]
        web_addr: Option<String>,
        #[arg(
            long,
            help = "Source only: approve automatic first sync at initialization"
        )]
        start_immediately: bool,
    },
    PeerAdd {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long, help = "Expected BLAKE3 fingerprint printed by peer init")]
        fingerprint: String,
    },
    Run {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, help = "Connect and run one source synchronization, then exit")]
        once: bool,
    },
    Status {
        #[arg(long)]
        root: PathBuf,
    },
    ExcludeAdd {
        #[arg(long)]
        root: PathBuf,
        path: String,
    },
    ExcludeRemove {
        #[arg(long)]
        root: PathBuf,
        path: String,
    },
    ExcludeList {
        #[arg(long)]
        root: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Source,
    Replica,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            role,
            root,
            addr,
            web_addr,
            start_immediately,
        } => {
            let role = match role {
                RoleArg::Source => Role::Source,
                RoleArg::Replica => Role::Replica,
            };
            let config = Config::init(root, role, addr, web_addr, start_immediately)?;
            let fingerprint = identity::create(&config)?;
            state::open(&config)?;
            println!("initialized {} at {}", config.role, config.root.display());
            println!("CA certificate: {}", config.ca_path().display());
            println!("fingerprint: {fingerprint}");
        }
        Command::PeerAdd {
            root,
            cert,
            fingerprint,
        } => {
            let config = Config::load(root)?;
            identity::add_peer(&config, &cert, &fingerprint)?;
            println!("peer trusted: {}", fingerprint.to_lowercase());
        }
        Command::Run { root, once } => {
            let config = Config::load(root)?;
            if config.role == Role::Replica || once {
                identity::require_peer(&config)?;
            }
            let _lock = state::lock_run(&config)?;
            let db = state::open(&config)?;
            match config.role {
                Role::Source => engine::run_source(config, db, once).await,
                Role::Replica if once => bail!("--once is only supported on a source"),
                Role::Replica => engine::run_replica(config, db).await,
            }?;
        }
        Command::Status { root } => {
            let config = Config::load(root).context("load node configuration")?;
            let db = state::open_readonly(&config)?;
            println!("role: {}", config.role);
            println!("root: {}", config.root.display());
            println!(
                "address: {}",
                config
                    .addr
                    .map_or_else(|| "-".into(), |addr| addr.to_string())
            );
            if config.role == Role::Source {
                println!("web_address: {}", config.web_addr);
                println!("paused: {}", config.pause_path().exists());
                println!("first_sync_confirmed: {}", config.first_sync_confirmed);
            }
            println!("hash_workers: {}", config.hash_workers);
            println!("verify_interval_secs: {}", config.verify_interval_secs);
            println!("peer configured: {}", config.peer_path().exists());
            println!("excludes: {}", config.excludes.join(", "));
            for key in [
                "connection",
                "pending_files",
                "last_success",
                "last_error",
                "last_files",
                "last_bytes",
                "last_scan_hashed",
                "last_scan_cached",
                "last_scan_workers",
                "last_scan_reused",
                "last_scan_ms",
                "last_transfer_ms",
                "verify_hashed_files",
                "verify_hashed_bytes",
                "verify_reused_files",
            ] {
                println!(
                    "{key}: {}",
                    state::get(&db, key)?.unwrap_or_else(|| "-".into())
                );
            }
        }
        Command::ExcludeAdd { root, path } => {
            let mut config = Config::load(root)?;
            if config.role != Role::Source {
                bail!("exclusions are configured on the source");
            }
            config::validate_excludes(std::slice::from_ref(&path))?;
            if !config.excludes.contains(&path) {
                config.excludes.push(path.clone());
                config.save()?;
            }
            println!("excluded: {path}");
        }
        Command::ExcludeRemove { root, path } => {
            let mut config = Config::load(root)?;
            if config.role != Role::Source {
                bail!("exclusions are configured on the source");
            }
            if !config.excludes.contains(&path) {
                bail!("exclusion not found: {path}");
            }
            config.excludes.retain(|existing| existing != &path);
            config.save()?;
            println!("exclusion removed: {path}");
        }
        Command::ExcludeList { root } => {
            let config = Config::load(root)?;
            for path in &config.excludes {
                println!("{path}");
            }
        }
    }
    Ok(())
}
