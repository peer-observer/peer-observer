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
        sync::{oneshot, watch},
        time::{self, Duration},
    },
};
use std::net::SocketAddr;

mod ipc;
mod metrics;

use metrics::Metrics;
use ipc::{ChainCallbacks, EventFut, IpcClient, IpcReader};

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
        .with_context(|| format!("connecting to NATS at {}", &args.nats.address))?;
    log::info!("Connected to NATS server at {}", &args.nats.address);

    let stream = UnixStream::connect(&args.ipc_socket_path)
        .await
        .with_context(|| {
            format!(
                "connecting to IPC socket at --ipc-socket-path '{}'",
                args.ipc_socket_path
            )
        })?;
    log::info!("Connected to IPC socket at {}", &args.ipc_socket_path);

    let mut ipc = IpcClient::connect(stream)
        .await
        .context("initializing the IPC session")?;
    let chain_listener = ipc
        .subscribe_chain_notifications(make_chain_callbacks(nats_client.clone()))
        .await
        .context("subscribing to Chain notifications")?;

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

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = fetch_and_publish_tip(&ipc.reader, &nats_client, &metrics).await {
                    log::error!("Could not fetch and publish 'BlockTip': {:#}", e);
                }
            }
            res = &mut ipc.rpc_task => {
                match res {
                    Ok(Ok(())) => log::warn!("Lost IPC connection to bitcoin-node."),
                    Ok(Err(e)) => log::error!("Lost IPC connection to bitcoin-node: {e}"),
                    Err(e) => log::error!("IPC task panicked or was cancelled: {e}"),
                }
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

    if ipc.rpc_task.is_finished() {
        return Ok(());
    }

    if let Err(e) = chain_listener.shutdown().await {
        log::error!("could not shut down listener: {}", e);
    }
    if let Err(e) = ipc.disconnector.await {
        log::error!("could not run disconnector during shutdown: {}", e);
    }
    let _ = ipc.rpc_task.await;
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

async fn fetch_and_publish_tip(
    reader: &IpcReader,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    let tip = match measure_ipc_call("get_tip", metrics, reader.get_tip())
        .await
        .context("measuring get_tip IPC")?
    {
        Some(t) => t,
        None => return Ok(()), // the node has no tip loaded yet, skip NATS publish
    };

    let proto = Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
        ipc_event: Some(ipc_extractor::ipc::IpcEvent::BlockTip(tip)),
    }))
    .context("creating the protobuf block tip event")?;
    nats_client
        .publish(Subject::Ipc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["get_tip"])
                .inc();
        })
        .context("publishing the block tip to NATS")?;
    Ok(())
}

fn make_chain_callbacks(nats: async_nats::Client) -> ChainCallbacks {
    ChainCallbacks {
        on_block_connected: wrap_publisher(nats.clone(), IpcEvent::BlockConnected),
        on_block_disconnected: wrap_publisher(nats.clone(), IpcEvent::BlockDisconnected),
        on_tx_added: wrap_publisher(nats.clone(), IpcEvent::TransactionAddedToMempool),
        on_tx_removed: wrap_publisher(nats.clone(), IpcEvent::TransactionRemovedFromMempool),
        on_chain_state_flushed: wrap_publisher(nats, IpcEvent::ChainStateFlushed),
        on_updated_block_tip: Box::new(|| {
            Box::pin(async move {
                log::debug!("updated_block_tip notification received");
            })
        }),
    }
}

fn wrap_publisher<T: 'static>(
    nats: async_nats::Client,
    variant: fn(T) -> IpcEvent,
) -> Box<dyn Fn(T) -> EventFut> {
    Box::new(move |value: T| {
        let nats = nats.clone();
        let event_inner = variant(value);
        Box::pin(async move {
            let event = match Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
                ipc_event: Some(event_inner),
            })) {
                Ok(e) => e,
                Err(e) => {
                    log::error!("Event build failed: {e}");
                    return;
                }
            };
            if let Err(e) = nats
                .publish(Subject::Ipc.to_string(), event.encode_to_vec().into())
                .await
            {
                log::error!("NATS publish failed: {e}");
            }
        })
    })
}
