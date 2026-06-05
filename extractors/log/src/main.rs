use log_extractor::Args;
use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let log_handle = tokio::spawn(log_extractor::run(args, shutdown_rx));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            shutdown_tx.send(true).context("sending shutdown signal")
        }
        result = log_handle => {
            match result.context("log-extractor runtime")? {
                Ok(()) => log::info!("log-extractor finished"),
                Err(e) => {
                    log::error!("log-extractor failed: {:#}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}
