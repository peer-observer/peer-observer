use shared::{
    async_nats,
    clap::{self, Parser},
    log,
    nats_subjects::Subject,
    nats_util::{self, NatsArgs},
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        ipc_extractor,
    },
    tokio::{
        self,
        net::UnixStream,
        sync::watch,
        time::{self, Duration},
    },
};
use std::io;

mod error;
use error::RuntimeError;

mod ipc;
use ipc::IpcClient;

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

    /// A path to an UNIX socket to read IPC data from.
    #[arg(short, long)]
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
    let nats_client = nats_util::prepare_connection(&args.nats)?
        .connect(&args.nats.address)
        .await?;
    log::info!("Connected to NATS server at {}", &args.nats.address);

    let stream = UnixStream::connect(&args.ipc_socket_path)
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "could not connect to IPC socket at --ipc-socket-path '{}': {}",
                    &args.ipc_socket_path, e
                ),
            )
        })?;
    log::info!("Connected to IPC socket at {}", &args.ipc_socket_path);

    let ipc_session = IpcClient::init(stream).await?;

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core IPC interface every {:?}.",
        duration_sec
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = get_tip(&ipc_session, &nats_client).await {
                        log::error!("Could not fetch and publish 'getHeight': {}", e)
                    }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("ipc_extractor received shutdown signal.");
                            ipc_session.rpc_task.abort();
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        ipc_session.rpc_task.abort();
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn get_tip(
    ipc_client: &IpcClient,
    nats_client: &async_nats::Client,
) -> Result<(), RuntimeError> {
    let tip = match ipc_client.get_tip().await? {
        Some(t) => t,
        None => return Ok(()), // the node has no tip loaded yet, skip NATS publish
    };

    let proto = Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
        ipc_event: Some(ipc_extractor::ipc::IpcEvent::BlockTip(tip)),
    }))?;

    nats_client
        .publish(Subject::Ipc.to_string(), proto.encode_to_vec().into())
        .await?;
    Ok(())
}
