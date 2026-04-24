use metrics::Args;
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("metrics tool error: {}", e);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_handle = tokio::spawn(metrics::run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            let _ = shutdown_tx.send(true);
        }
        result = metrics_handle => {
            match result.unwrap() {
                Ok(_) => log::info!("metrics task completed."),
                Err(e) => log::error!("metrics task failed: {e}"),
            }
        }
    }
}
