use shared::{
    anyhow::{Context, Result},
    async_nats,
    clap::{self, Parser},
    log,
    nats_subjects::Subject,
    nats_util,
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        ipc_extractor::{self, ipc::IpcEvent},
    },
    tokio::{
        self,
        net::UnixStream,
        sync::{
            mpsc::{self, error::TrySendError},
            oneshot, watch,
        },
        time::{self, Duration},
    },
};
use std::net::SocketAddr;

mod chain_notifications;
mod ipc;
mod metrics;

use ipc::connect_stream;
use metrics::Metrics;

/// Number of notifications that can wait to be published before new ones are dropped.
const NOTIFICATION_CHANNEL_CAPACITY: usize = 4096;

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

    /// Address to serve Prometheus metrics on.
    #[arg(long, default_value = "127.0.0.1:8285")]
    pub prometheus_address: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
    bound_addr_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let nats_client = nats_util::prepare_connection(&args.nats)
        .context("preparing NATS connection")?
        .connect(&args.nats.address)
        .await
        .with_context(|| format!("connecting to NATS at {}", args.nats.address))?;
    log::info!("Connected to NATS server at {}", args.nats.address);

    let stream = UnixStream::connect(&args.ipc_socket_path)
        .await
        .with_context(|| {
            format!(
                "connecting to IPC socket at --ipc-socket-path '{}'",
                args.ipc_socket_path
            )
        })?;
    log::info!("Connected to IPC socket at {}", args.ipc_socket_path);

    let (mut ipc_client, mut connection) = connect_stream(stream)
        .await
        .context("bootstrapping and initializing IPC capabilities")?;

    let (notifications_tx, mut notifications) = mpsc::channel(NOTIFICATION_CHANNEL_CAPACITY);
    ipc_client
        .chain_handle_notifications(Box::new(move |event| {
            if let Err(TrySendError::Full(_)) = notifications_tx.try_send(event) {
                log::warn!("Notificacion handling queue is full. Dropping a notification...");
            }
        }))
        .await
        .context("subscribing to chain notifications")?;

    let metrics = Metrics::new().context("creating metrics registry")?;
    let local_addr =
        shared::metricserver::start(&args.prometheus_address, Some(metrics.registry.clone()))
            .with_context(|| format!("starting metrics server on {}", args.prometheus_address))?;
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core IPC interface every {:?}.",
        duration_sec
    );

    let mut connection_lost = false;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // nothing polls yet.
            }
            Some(event) = notifications.recv() => {
                match event {
                    IpcEvent::UpdatedBlockTip(_) => {
                        let tip = match measure_ipc_call("mining_get_tip", &metrics, ipc_client.mining_get_tip())
                            .await
                            .context("measuring mining_get_tip IPC")?
                        {
                            Some(t) => t,
                            None => return Ok(()), // the node has no tip loaded yet, skip NATS publish
                        };
                        let publish_result = publish_ipc_event(IpcEvent::BlockTip(tip), &nats_client)
                            .await
                            .inspect_err(|_| {
                                metrics
                                    .nats_publish_errors
                                    .with_label_values(&["mining_get_tip"])
                                    .inc();
                            })
                            .context("publishing the block tip to NATS");
                        if let Err(e) = publish_result {
                            log::error!("Error publishing 'BlockTip': {:#}", e);
                        }
                    }
                    event => {
                        if let Err(e) = publish_ipc_event(event, &nats_client).await {
                            log::error!("Could not publish IPC notification: {:#}", e);
                        }
                    }
                }
            }
            res = connection.closed() => {
                match res {
                    Ok(()) => log::warn!("Lost IPC connection to bitcoin-node."),
                    Err(e) => log::error!("Lost IPC connection to bitcoin-node: {e:#}"),
                }
                connection_lost = true;
                break;
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) if *shutdown_rx.borrow() => {
                        log::info!("ipc_extractor received shutdown signal.");
                    }
                    _ => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                    }
                }
                break;
            }
        }
    }

    // Only clean up while the connection is still alive.
    if !connection_lost {
        if let Err(e) = ipc_client.release().await {
            log::error!("Error while releasing capabilities: {:#}", e);
        }
        connection.shutdown().await;
    }
    Ok(())
}

async fn measure_ipc_call<T, E, Fut>(method_name: &str, metrics: &Metrics, fut: Fut) -> Result<T, E>
where
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let timer = metrics
        .ipc_fetch_duration
        .with_label_values(&[method_name])
        .start_timer();
    let res = fut.await;
    match &res {
        Ok(_) => {
            timer.stop_and_record();
        }
        Err(_) => {
            timer.stop_and_discard();
            metrics
                .ipc_fetch_errors
                .with_label_values(&[method_name])
                .inc();
        }
    }
    res
}

async fn publish_ipc_event(event: IpcEvent, nats_client: &async_nats::Client) -> Result<()> {
    let proto = Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
        ipc_event: Some(event),
    }))
    .context("creating the protobuf IPC event")?;
    nats_client
        .publish(Subject::Ipc.to_string(), proto.encode_to_vec().into())
        .await
        .context("publishing the IPC event to NATS")?;
    Ok(())
}
