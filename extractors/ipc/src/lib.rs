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

    let metrics = Metrics::new().context("creating metrics registry")?;
    let local_addr =
        shared::metricserver::start(&args.prometheus_address, Some(metrics.registry.clone()))
            .with_context(|| format!("starting metrics server on {}", args.prometheus_address))?;
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }

    let mut ipc = IpcClient::connect(stream).await?;
    let chain_listener = ipc
        .subscribe_chain_notifications(make_chain_callbacks(
            nats_client.clone(),
            ipc.reader.clone(),
            metrics.clone(),
        ))
        .await?;

    let mut poll_handle = tokio::task::spawn_local(poll_task(args.query_interval));

    tokio::select! {
        res = &mut poll_handle => {
            match res {
                Ok(()) => log::info!("Poll task exited."),
                Err(e) => log::error!("Poll task panicked: {e}"),
            }
        }
        res = &mut ipc.rpc_task => {
            match res {
                Ok(Ok(())) => log::warn!("Lost IPC connection to bitcoin-node."),
                Ok(Err(e)) => log::error!("Lost IPC connection to bitcoin-node: {e}"),
                Err(e) => log::error!("IPC task panicked or was cancelled: {e}"),
            }
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

async fn poll_task(interval_secs: u64) {
    let duration_sec = Duration::from_secs(interval_secs);
    log::info!(
        "Querying the Bitcoin Core IPC interface every {:?}.",
        duration_sec
    );
    let mut interval = time::interval(duration_sec);

    loop {
        interval.tick().await;
    }
}

fn make_chain_callbacks(
    nats: async_nats::Client,
    reader: IpcReader,
    metrics: Metrics,
) -> ChainCallbacks {
    ChainCallbacks {
        on_block_connected: wrap_publisher(nats.clone(), IpcEvent::BlockConnected),
        on_block_disconnected: wrap_publisher(nats.clone(), IpcEvent::BlockDisconnected),
        on_tx_added: wrap_publisher(nats.clone(), IpcEvent::TransactionAddedToMempool),
        on_tx_removed: wrap_publisher(nats.clone(), IpcEvent::TransactionRemovedFromMempool),
        on_chain_state_flushed: wrap_publisher(nats.clone(), IpcEvent::ChainStateFlushed),

        // `updatedBlockTip` pushes no value to the subscriber
        // so we fetch through the reader the new tip and publish
        // a BlockTip event to NATS.
        on_updated_block_tip: Box::new(move || {
            let nats = nats.clone();
            let reader = reader.clone();
            let metrics = metrics.clone();
            Box::pin(async move {
                match measure_ipc_call("get_tip", &metrics, reader.get_tip()).await {
                    Ok(Some(tip)) => publish_ipc_event(&nats, IpcEvent::BlockTip(tip)).await,
                    Ok(None) => unreachable!("updatedBlockTip fired without a tip"),
                    Err(e) => log::error!("could not get tip on updated_block_tip: {}", e),
                }
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
        Box::pin(async move { publish_ipc_event(&nats, event_inner).await })
    })
}

async fn publish_ipc_event(nats: &async_nats::Client, ipc_event: IpcEvent) {
    match Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
        ipc_event: Some(ipc_event),
    })) {
        Ok(proto) => {
            if let Err(e) = nats
                .publish(Subject::Ipc.to_string(), proto.encode_to_vec().into())
                .await
            {
                log::error!("could not publish IPC event into NATS: {}", e);
            } else {
                log::trace!("published IPC event into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!("could not create IPC event protobuf: {}", e);
        }
    }
}
