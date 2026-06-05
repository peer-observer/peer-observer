use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};
use websocket::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // No bound address notification needed in production (used in tests to
    // communicate the OS-assigned port back when binding to port 0).
    let websocket_handle = tokio::spawn(websocket::run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            shutdown_tx.send(true).context("sending shutdown signal")
        }
        result = websocket_handle => {
            match result.context("websocket runtime")? {
                Ok(()) => log::info!("websocket finished"),
                Err(e) => {
                    log::error!("websocket failed: {:#}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}
