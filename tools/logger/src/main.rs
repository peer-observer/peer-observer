use logger::Args;
use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let logger_handle = tokio::spawn(logger::run(args, shutdown_rx));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            shutdown_tx.send(true).context("sending shutdown signal")
        }
        result = logger_handle => {
            match result.context("logger runtime")? {
                Ok(()) => log::info!("logger finished"),
                Err(e) => {
                    log::error!("logger failed: {:#}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}
