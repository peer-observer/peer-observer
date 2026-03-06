use shared::clap::{self, Parser};
use shared::log;
use shared::nats_util::{self, NatsArgs};
use shared::tokio::sync::watch;
use shared::tokio::time::{self, Duration};

mod error;

use error::RuntimeError;

/// The peer-observer ipc-extractor periodically queries data from the
/// Bitcoin Core IPC interface and publishes the results as events into
/// a NATS pub-sub queue.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html.
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,

    /// A UNIX socket path to read IPC data from.
    #[arg(long)]
    pub ipc_socket_path: String,

    /// Interval (in seconds) in which to query from the Bitcoin Core IPC interface.
    #[arg(long, default_value_t = 10)]
    pub query_interval: u64,
}

impl Args {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nats: NatsArgs,
        log_level: log::Level,
        ipc_socket_path: String,
        query_interval: u64,
    ) -> Args {
        Self {
            nats,
            log_level,
            ipc_socket_path,
            query_interval,
        }
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    // let nats_client = nats_util::prepare_connection(&args.nats)?
    //     .connect(&args.nats.address)
    //     .await?;
    log::info!("Connected to NATS server at {}", &args.nats.address);

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core IPC interface every {:?}.",
        duration_sec
    );

    loop {
        shared::tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = foo(/* &nats_client */).await {
                        log::error!("Could not fetch and publish 'foo': {}", e)
                    }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("ipc_extractor received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn foo() -> Result<(), RuntimeError> {
    Ok(())
}
