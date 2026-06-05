use shared::anyhow::{Context, Result};
use shared::clap::{ArgGroup, Parser};
use shared::corepc_client::client_sync::Auth;
use shared::corepc_client::client_sync::v30::{Client, FeeEstimateMode};
use shared::log;
use shared::nats_subjects::Subject;
use shared::nats_util;
use shared::prost::Message;
use shared::protobuf::event::{Event, event::PeerObserverEvent};
use shared::protobuf::rpc_extractor::{self, EstimateSmartFee};
use shared::tokio::sync::{oneshot, watch};
use shared::tokio::time::{self, Duration};
use shared::{async_nats, clap};
use std::net::SocketAddr;

pub mod metrics;

use metrics::Metrics;

/// The peer-observer rpc-extractor periodically queries data from the
/// Bitcoin Core RPC endpoint and publishes the results as events into
/// a NATS pub-sub queue.
#[derive(Parser, Debug)]
#[clap(group(
    ArgGroup::new("auth")
        .required(true)
        .multiple(false)
        .args(&["rpc_cookie_file", "rpc_user"])
))]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html.
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,

    /// Address of the Bitcoin Core RPC endpoint the RPC extractor will query.
    #[arg(long, default_value = "127.0.0.1:8332")]
    pub rpc_host: String,

    /// RPC username for authentication with the Bitcoin Core RPC endpoint.
    #[arg(long)]
    pub rpc_user: Option<String>,

    /// RPC password for authentication with the Bitcoin Core RPC endpoint.
    #[arg(requires = "rpc_user", long)]
    pub rpc_password: Option<String>,

    /// An RPC cookie file for authentication with the Bitcoin Core RPC endpoint.
    #[arg(long)]
    pub rpc_cookie_file: Option<String>,

    /// Interval (in seconds) in which to query from the Bitcoin Core RPC endpoint.
    #[arg(long, default_value_t = 10)]
    pub query_interval: u64,

    /// Interval (in seconds) in which to query resource-intensive or less frequently changing RPCs from the Bitcoin Core RPC endpoint.
    /// These currently include:
    /// - getchaintxstats (infrequent changes)
    /// - getblockchaininfo (infrequent changes)
    /// - getrawaddrman (resource intensive)
    #[arg(long, default_value_t = 120)]
    pub query_interval_less_frequent: u64,

    /// Address to serve Prometheus metrics on.
    #[arg(long, default_value = "127.0.0.1:8284")]
    pub prometheus_address: String,

    /// Disable querying and publishing of `getpeerinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getpeerinfo: bool,

    /// Disable querying and publishing of `getmempoolinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getmempoolinfo: bool,

    /// Disable querying and publishing of `uptime` data.
    #[arg(long, default_value_t = false)]
    pub disable_uptime: bool,

    /// Disable querying and publishing of `getnettotals` data.
    #[arg(long, default_value_t = false)]
    pub disable_getnettotals: bool,

    /// Disable querying and publishing of `getmemoryinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getmemoryinfo: bool,

    /// Disable querying and publishing of `getaddrmaninfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getaddrmaninfo: bool,

    /// Disable querying and publishing of `getchaintxstats` data.
    #[arg(long, default_value_t = false)]
    pub disable_getchaintxstats: bool,

    /// Disable querying and publishing of `getnetworkinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getnetworkinfo: bool,

    /// Disable querying and publishing of `getblockchaininfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getblockchaininfo: bool,

    /// Disable querying and publishing of `getorphantxs` data.
    #[arg(long, default_value_t = false)]
    pub disable_getorphantxs: bool,

    /// Disable querying and publishing of `getrawaddrman` data.
    #[arg(long, default_value_t = false)]
    pub disable_getrawaddrman: bool,

    /// Disable querying and publishing of `estimatesmartfee` data.
    #[arg(long, default_value_t = false)]
    pub disable_estimatesmartfee: bool,
    // when adding more disable_* args, make sure to update the disable_all below
}

pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
    bound_addr_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let metrics = Metrics::new().context("creating metrics registry")?;

    let auth: Auth = match args.rpc_cookie_file {
        Some(path) => Auth::CookieFile(path.into()),
        None => Auth::UserPass(
            args.rpc_user.expect("need an RPC user"),
            args.rpc_password.expect("need an RPC password"),
        ),
    };
    let rpc_client = Client::new_with_auth(&format!("http://{}", args.rpc_host), auth)
        .context("creating new RPC client")?;

    let nats_client = nats_util::prepare_connection(&args.nats)
        .context("preparing NATS connection")?
        .connect(&args.nats.address)
        .await
        .with_context(|| format!("connecting to NATS at {}", &args.nats.address))?;
    log::info!("Connected to NATS server at {}", &args.nats.address);

    // Start the metric server with our custom registry. This happens after
    // the RPC client and NATS connection are set up so that any startup
    // failure surfaces through the readiness barrier in tests (which races
    // bound_addr_tx against the extractor task handle) instead of leaving
    // the test to time out. Matches the order used in p2p_extractor::run.
    let local_addr =
        shared::metricserver::start(&args.prometheus_address, Some(metrics.registry.clone()))
            .context("starting metrics server")?;

    // Notify the caller of the actual bound address (used in tests with port 0).
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core RPC interface every {:?}.",
        duration_sec
    );

    // Use a separate interval for queries that can be run less frequently
    let duration_sec_less_frequent = Duration::from_secs(args.query_interval_less_frequent);
    let mut less_frequent_interval = time::interval(duration_sec_less_frequent);
    log::info!(
        "Querying the Bitcoin Core RPC interface for 'less-frequent' RPCs every {:?}.",
        duration_sec_less_frequent
    );

    log::info!(
        "Querying getpeerinfo enabled:    {}",
        !args.disable_getpeerinfo
    );
    log::info!(
        "Querying getmempoolinfo enabled: {}",
        !args.disable_getmempoolinfo
    );
    log::info!("Querying uptime enabled:         {}", !args.disable_uptime);
    log::info!(
        "Querying getnettotals enabled:   {}",
        !args.disable_getnettotals
    );
    log::info!(
        "Querying getmemoryinfo enabled:  {}",
        !args.disable_getmemoryinfo
    );
    log::info!(
        "Querying getaddrmaninfo enabled: {}",
        !args.disable_getaddrmaninfo
    );
    log::info!(
        "Querying getchaintxstats enabled: {}",
        !args.disable_getchaintxstats
    );
    log::info!(
        "Querying getnetworkinfo enabled: {}",
        !args.disable_getnetworkinfo
    );
    log::info!(
        "Querying getblockchaininfo enabled: {}",
        !args.disable_getblockchaininfo
    );
    log::info!(
        "Querying getorphantxs enabled: {}",
        !args.disable_getorphantxs
    );
    log::info!(
        "Querying getrawaddrman enabled: {}",
        !args.disable_getrawaddrman
    );
    log::info!(
        "Querying estimatesmartfee enabled: {}",
        !args.disable_estimatesmartfee
    );
    // check if we have at least one RPC to query
    let disable_all = args.disable_getpeerinfo
        && args.disable_getmempoolinfo
        && args.disable_uptime
        && args.disable_getnettotals
        && args.disable_getmemoryinfo
        && args.disable_getaddrmaninfo
        && args.disable_getchaintxstats
        && args.disable_getnetworkinfo
        && args.disable_getblockchaininfo
        && args.disable_getorphantxs
        && args.disable_getrawaddrman
        && args.disable_estimatesmartfee;
    if disable_all {
        log::warn!("No RPC configured to be queried!");
    }

    // Runs `$func` against the RPC and NATS clients unless its `disable_*` flag
    // is set, logging (but not propagating) any error. `rpc_client`,
    // `nats_client` and `metrics` are captured from this scope.
    macro_rules! fetch {
        ($disabled:expr, $func:ident) => {
            if !$disabled {
                if let Err(e) = $func(&rpc_client, &nats_client, &metrics).await {
                    log::error!(
                        "Could not fetch and publish '{}': {:#}",
                        stringify!($func),
                        e
                    );
                }
            }
        };
    }

    loop {
        shared::tokio::select! {
            _ = interval.tick() => {
                fetch!(args.disable_getpeerinfo, getpeerinfo);
                fetch!(args.disable_getmempoolinfo, getmempoolinfo);
                fetch!(args.disable_uptime, uptime);
                fetch!(args.disable_getnettotals, getnettotals);
                fetch!(args.disable_getmemoryinfo, getmemoryinfo);
                fetch!(args.disable_getaddrmaninfo, getaddrmaninfo);
                fetch!(args.disable_getnetworkinfo, getnetworkinfo);
                fetch!(args.disable_getorphantxs, getorphantxs);
                fetch!(args.disable_estimatesmartfee, estimatesmartfee);
            }
            _ = less_frequent_interval.tick() => {
                // make sure to update the Args docs when changing these:
                fetch!(args.disable_getchaintxstats, getchaintxstats);
                fetch!(args.disable_getblockchaininfo, getblockchaininfo);
                fetch!(args.disable_getrawaddrman, getrawaddrman);
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("rpc_extractor received shutdown signal.");
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

fn measure_rpc_call<T, E, F>(method_name: &str, metrics: &Metrics, f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    let timer = metrics
        .rpc_fetch_duration
        .with_label_values(&[method_name])
        .start_timer();
    let res = f();
    match &res {
        Ok(_) => {
            timer.stop_and_record();
        }
        Err(_) => {
            timer.stop_and_discard();
            metrics
                .rpc_fetch_errors
                .with_label_values(&[method_name])
                .inc();
        }
    }
    res
}

async fn publish_to_nats(
    event: &Event,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
    method_name: &str,
) -> Result<()> {
    nats_client
        .publish(Subject::Rpc.to_string(), event.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&[method_name])
                .inc();
        })
        .with_context(|| format!("publishing {method_name} result to NATS"))
}

/// Fetches data via `call`, turns the raw RPC response into an `RpcEvent` using
/// `to_event` (which applies `.into_model()` / `.into()` as needed), wraps it in
/// a protobuf `Event`, and publishes it to NATS.
///
/// Errors are recorded against the per-stage metrics counters: a fetch failure
/// via [`measure_rpc_call`] (`rpc_fetch_errors`), a `to_event` failure (e.g. a
/// model conversion) via `rpc_model_errors`, and a publish failure via
/// `nats_publish_errors`.
async fn fetch_and_publish<R, E, F, M>(
    method_name: &str,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
    call: F,
    to_event: M,
) -> Result<()>
where
    F: FnOnce() -> Result<R, E>,
    E: std::error::Error + Send + Sync + 'static,
    M: FnOnce(R) -> Result<rpc_extractor::rpc::RpcEvent>,
{
    let response = measure_rpc_call(method_name, metrics, call)
        .with_context(|| format!("measuring the {method_name} RPC call"))?;

    let rpc_event = to_event(response)
        .inspect_err(|_| {
            metrics
                .rpc_model_errors
                .with_label_values(&[method_name])
                .inc();
        })
        .with_context(|| format!("building the {method_name} event payload"))?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_event),
    }))
    .with_context(|| format!("creating the protobuf {method_name} event"))?;

    publish_to_nats(&proto, nats_client, metrics, method_name).await
}

async fn getpeerinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getpeerinfo",
        nats_client,
        metrics,
        || rpc_client.get_peer_info(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::PeerInfos(r.into())),
    )
    .await
}

async fn getmempoolinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getmempoolinfo",
        nats_client,
        metrics,
        || rpc_client.get_mempool_info(),
        |r| {
            Ok(rpc_extractor::rpc::RpcEvent::MempoolInfo(
                r.into_model()?.into(),
            ))
        },
    )
    .await
}

async fn uptime(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "uptime",
        nats_client,
        metrics,
        || rpc_client.uptime(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::Uptime(r)),
    )
    .await
}

async fn getnettotals(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getnettotals",
        nats_client,
        metrics,
        || rpc_client.get_net_totals(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::NetTotals(r.into())),
    )
    .await
}

async fn getmemoryinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getmemoryinfo",
        nats_client,
        metrics,
        || rpc_client.get_memory_info(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::MemoryInfo(r.into())),
    )
    .await
}

async fn getaddrmaninfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getaddrmaninfo",
        nats_client,
        metrics,
        || rpc_client.get_addr_man_info(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::AddrmanInfo(r.into())),
    )
    .await
}

async fn getchaintxstats(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getchaintxstats",
        nats_client,
        metrics,
        || rpc_client.get_chain_tx_stats(),
        |r| {
            Ok(rpc_extractor::rpc::RpcEvent::ChainTxStats(
                r.into_model()?.into(),
            ))
        },
    )
    .await
}

async fn getnetworkinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getnetworkinfo",
        nats_client,
        metrics,
        || rpc_client.get_network_info(),
        |r| {
            Ok(rpc_extractor::rpc::RpcEvent::NetworkInfo(
                r.into_model()?.into(),
            ))
        },
    )
    .await
}

async fn getblockchaininfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getblockchaininfo",
        nats_client,
        metrics,
        || rpc_client.get_blockchain_info(),
        |r| {
            Ok(rpc_extractor::rpc::RpcEvent::BlockchainInfo(
                r.into_model()?.into(),
            ))
        },
    )
    .await
}

async fn getorphantxs(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getorphantxs",
        nats_client,
        metrics,
        || rpc_client.get_orphan_txs_verbosity_2(),
        |r| {
            Ok(rpc_extractor::rpc::RpcEvent::OrphanTxs(
                r.into_model()?.into(),
            ))
        },
    )
    .await
}

async fn getrawaddrman(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    fetch_and_publish(
        "getrawaddrman",
        nats_client,
        metrics,
        || rpc_client.get_raw_addrman(),
        |r| Ok(rpc_extractor::rpc::RpcEvent::Addrman(r.into())),
    )
    .await
}

async fn estimatesmartfee(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<()> {
    const BLOCKS_10MIN: u32 = 1;
    const BLOCKS_1HOUR: u32 = 6;
    const BLOCKS_1DAY: u32 = 144;
    const BLOCK_TARGETS: [u32; 3] = [BLOCKS_10MIN, BLOCKS_1HOUR, BLOCKS_1DAY];

    const MODES: [FeeEstimateMode; 2] =
        [FeeEstimateMode::Economical, FeeEstimateMode::Conservative];

    for target in BLOCK_TARGETS {
        for mode in MODES {
            fetch_and_publish(
                "estimatesmartfee",
                nats_client,
                metrics,
                || rpc_client.estimate_smart_fee_with_mode(target, mode),
                |r| {
                    let estimate = r.into_model()?;
                    Ok(rpc_extractor::rpc::RpcEvent::EstimateSmartFee(
                        EstimateSmartFee::from_rpc(estimate, target, mode.into()),
                    ))
                },
            )
            .await?;
        }
    }

    Ok(())
}
