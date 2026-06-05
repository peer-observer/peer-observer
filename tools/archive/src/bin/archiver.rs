use archive::archiver::{run, Args};
use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut archiver_handle = tokio::spawn(run(args, shutdown_rx));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            shutdown_tx.send(true).context("sending shutdown signal")?;
        }
        result = &mut archiver_handle => {
            if let Err(e) = result.context("joining archiver task")? {
                log::error!("archiver failed: {:#}", e);
                std::process::exit(1);
            }
            log::info!("archiver finished");
            return Ok(());
        }
    }

    // Ctrl+C path: wait for the archiver to flush and close its files cleanly.
    if let Err(e) = archiver_handle.await.context("joining archiver task")? {
        log::error!("archiver failed: {:#}", e);
        std::process::exit(1);
    }
    log::info!("archiver finished");
    Ok(())
}
