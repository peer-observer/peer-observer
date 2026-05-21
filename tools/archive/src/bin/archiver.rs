use archive::archiver::{run, Args};
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("archiver tool error: {}", e);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut archiver_handle = tokio::spawn(run(args, shutdown_rx));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            let _ = shutdown_tx.send(true);
        }
        result = &mut archiver_handle => {
            match result.unwrap() {
                Ok(_) => log::info!("archiver task completed."),
                Err(e) => log::error!("archiver task failed: {e}"),
            }
            return;
        }
    }

    match archiver_handle.await.unwrap() {
        Ok(_) => log::info!("archiver task completed."),
        Err(e) => log::error!("archiver task failed: {e}"),
    }
}
