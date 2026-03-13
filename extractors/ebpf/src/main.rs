use ebpf_extractor::Args;
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::clap::Parser;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn Ctrl+C handler to send shutdown signal.
    // We can't tokio::spawn run() because libbpf types are !Send,
    // so run() executes directly on the main task instead.
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            log::info!("Received Ctrl+C. Stopping...");
            let _ = shutdown_tx.send(true);
        }
    });

    if let Err(e) = ebpf_extractor::run(args, shutdown_rx).await {
        log::error!("Fatal error during extractor runtime: {}", e);
    }
}
