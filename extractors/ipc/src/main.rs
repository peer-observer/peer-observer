use ipc_extractor::Args;
use shared::{
    clap::Parser,
    log, simple_logger,
    tokio::{self, signal, sync::watch, task::LocalSet},
};

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("ipc extractor error: {}", e);
    }

    LocalSet::new()
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let run_future = ipc_extractor::run(args, shutdown_rx);
            tokio::pin!(run_future);

            tokio::select! {
                _ = signal::ctrl_c() => {
                    log::info!("Received Ctrl+C. Stopping...");
                    let _ = shutdown_tx.send(true);
                    match run_future.await {
                        Ok(_) => log::info!("ipc-extractor task completed."),
                        Err(e) => log::error!("ipc-extractor task failed: {e}"),
                    }
                }
                result = &mut run_future => {
                    match result {
                        Ok(_) => log::info!("ipc-extractor task completed."),
                        Err(e) => log::error!("ipc-extractor task failed: {e}"),
                    }
                }
            }
        })
        .await;
}
