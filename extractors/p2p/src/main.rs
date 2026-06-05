use p2p_extractor::Args;
use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // No bound address notification needed in production (used in tests to
    // communicate the OS-assigned port back when binding to port 0).
    let p2p_handle = tokio::spawn(p2p_extractor::run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            shutdown_tx.send(true).context("sending shutdown signal")
        }
        result = p2p_handle => {
            match result.context("p2p-extractor runtime")? {
                Ok(()) => log::info!("p2p-extractor finished"),
                Err(e) => {
                    log::error!("p2p-extractor failed: {:#}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}
