use ipc_extractor::Args;
use shared::{
    anyhow::{Context, Result},
    clap::Parser,
    log, simple_logger,
    tokio::{self, signal, sync::watch, task::LocalSet},
};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    let result = LocalSet::new()
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let run_future = ipc_extractor::run(args, shutdown_rx, None);
            tokio::pin!(run_future);

            tokio::select! {
                _ = signal::ctrl_c() => {
                    log::info!("Received Ctrl+C. Stopping...");
                    let _ = shutdown_tx.send(true);
                    run_future.await
                }
                result = &mut run_future => result,
            }
        })
        .await;

    if let Err(e) = result {
        log::error!("ipc-extractor failed: {:#}", e);
        std::process::exit(1);
    }
    Ok(())
}
