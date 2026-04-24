use rpc_extractor::Args;
use shared::log;
use shared::tokio::{self, signal, sync::watch};
use shared::{clap::Parser, simple_logger};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("rpc extractor error: {}", e);
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let rpc_handle = tokio::spawn(rpc_extractor::run(args, shutdown_rx, None));

    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received Ctrl+C. Stopping...");
            let _ = shutdown_tx.send(true);
        }
        result = rpc_handle => {
            match result.unwrap() {
                Ok(_) => log::info!("rpc-extractor task completed."),
                Err(e) => log::error!("rpc-extractor task failed: {e}"),
            }
        }
    }
}
