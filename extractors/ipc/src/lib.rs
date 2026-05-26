use shared::{
    async_nats,
    clap::{self, Parser},
    log,
    nats_subjects::Subject,
    nats_util,
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
mod metrics;

use error::RuntimeError;
use metrics::Metrics;

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

    /// Address to serve Prometheus metrics on.
    #[arg(long, default_value = "127.0.0.1:8285")]
    pub prometheus_address: String,
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

    let mut ipc_session = IpcClient::init(stream).await?;

    let metrics = Metrics::new();
    shared::metricserver::start(&args.prometheus_address, Some(metrics.registry.clone()))?;

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core IPC interface every {:?}.",
        duration_sec
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = fetch_and_publish_tip(&ipc_session, &nats_client, &metrics).await {
                    log::error!("Could not fetch and publish 'BlockTip': {}", e);
                }
            }
            res = &mut ipc_session.rpc_task => {
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

    if let Err(e) = ipc_session.disconnector.await {
        log::error!("could not run disconnector during shutdown: {}", e);
    }
    if !ipc_session.rpc_task.is_finished() {
        let _ = ipc_session.rpc_task.await;
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

async fn fetch_and_publish_tip(
    ipc_client: &IpcClient,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), RuntimeError> {
    let tip = match measure_ipc_call("get_tip", metrics, ipc_client.get_tip()).await? {
        Some(t) => t,
        None => return Ok(()), // the node has no tip loaded yet, skip NATS publish
    };

    let proto = Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
        ipc_event: Some(ipc_extractor::ipc::IpcEvent::BlockTip(tip)),
    }))?;
    nats_client
        .publish(Subject::Ipc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["get_tip"])
                .inc();
        })?;
    Ok(())
}
