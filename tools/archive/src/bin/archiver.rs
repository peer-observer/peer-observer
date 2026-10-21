use archive::archiver::{run, Args};
use shared::anyhow::{Context, Result};
use shared::log;
use shared::tokio::{
    self,
    signal::{
        self,
        unix::{self, SignalKind},
    },
    sync::watch,
};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    // systemd and other service managers stop processes with SIGTERM. Handle
    // it like Ctrl+C so the archive file is finalized instead of truncated.
    let mut sigterm =
        unix::signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut archiver_handle = tokio::spawn(run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => log::info!("Received Ctrl+C. Stopping..."),
        _ = sigterm.recv() => log::info!("Received SIGTERM. Stopping..."),
        result = &mut archiver_handle => {
            if let Err(e) = result.context("joining archiver task")? {
                log::error!("archiver failed: {:#}", e);
                std::process::exit(1);
            }
            log::info!("archiver finished");
            return Ok(());
        }
    }
    shutdown_tx.send(true).context("sending shutdown signal")?;

    // Signal path: wait for the archiver to flush and close its files cleanly.
    if let Err(e) = archiver_handle.await.context("joining archiver task")? {
        log::error!("archiver failed: {:#}", e);
        std::process::exit(1);
    }
    log::info!("archiver finished");
    Ok(())
}
