use p2p_extractor::Args;
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("p2p extractor error: {}", e);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // No bound address notification needed in production (used in tests to
    // communicate the OS-assigned port back when binding to port 0).
    let p2p_handle = tokio::spawn(p2p_extractor::run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            let _ = shutdown_tx.send(true);
        }
        result = p2p_handle => {
            match result.unwrap() {
                Ok(_) => log::info!("p2p-extractor task completed."),
                Err(e) => log::error!("p2p-extractor task failed: {e}"),
            }
        }
    }
}
