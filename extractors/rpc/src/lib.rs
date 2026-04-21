use shared::clap::{ArgGroup, Parser};
use shared::corepc_client::client_sync::Auth;
use shared::corepc_client::client_sync::v30::{Client, FeeEstimateMode};
use shared::corepc_node::mtype::{
    GetBlockchainInfo, GetChainTxStats, GetNetworkInfo, GetOrphanTxsVerboseTwo,
};
use shared::log;
use shared::nats_subjects::Subject;
use shared::nats_util::{self, NatsArgs};
use shared::prost::Message;
use shared::protobuf::event::{Event, event::PeerObserverEvent};
use shared::protobuf::rpc_extractor::{self, EstimateSmartFee};
use shared::tokio::sync::watch;
use shared::tokio::time::{self, Duration};
use shared::{async_nats, clap};

mod error;
pub mod metrics;

use error::{FetchOrPublishError, RuntimeError};
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
}

impl Args {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nats: NatsArgs,
        log_level: log::Level,
        rpc_host: String,
        rpc_cookie_file: String,
        query_interval: u64,
        query_interval_less_frequent: u64,
        prometheus_address: String,
        disable_getpeerinfo: bool,
        disable_getmempoolinfo: bool,
        disable_uptime: bool,
        disable_getnettotals: bool,
        disable_getmemoryinfo: bool,
        disable_getaddrmaninfo: bool,
        disable_getchaintxstats: bool,
        disable_getnetworkinfo: bool,
        disable_getblockchaininfo: bool,
        disable_getorphantxs: bool,
        disable_getrawaddrman: bool,
        disable_estimatesmartfee: bool,
    ) -> Args {
        Self {
            nats,
            log_level,
            rpc_host,
            rpc_password: None,
            rpc_user: None,
            rpc_cookie_file: Some(rpc_cookie_file),
            query_interval,
            query_interval_less_frequent,
            prometheus_address,
            disable_getpeerinfo,
            disable_getmempoolinfo,
            disable_uptime,
            disable_getnettotals,
            disable_getmemoryinfo,
            disable_getaddrmaninfo,
            disable_getchaintxstats,
            disable_getnetworkinfo,
            disable_getblockchaininfo,
            disable_getorphantxs,
            disable_getrawaddrman,
            disable_estimatesmartfee,
            // when adding more disable_* args, make sure to update the disable_all below
        }
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    // Create metrics instance with its own registry
    let metrics = Metrics::new();

    // Start the metric server with our custom registry.
    shared::metricserver::start(&args.prometheus_address, Some(metrics.registry.clone()))?;

    let auth: Auth = match args.rpc_cookie_file {
        Some(path) => Auth::CookieFile(path.into()),
        None => Auth::UserPass(
            args.rpc_user.expect("need an RPC user"),
            args.rpc_password.expect("need an RPC password"),
        ),
    };
    let rpc_client = Client::new_with_auth(&format!("http://{}", args.rpc_host), auth)?;

    let nats_client = nats_util::prepare_connection(&args.nats)?
        .connect(&args.nats.address)
        .await?;
    log::info!("Connected to NATS server at {}", &args.nats.address);

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

    loop {
        shared::tokio::select! {
            _ = interval.tick() => {
                if !args.disable_getpeerinfo
                    && let Err(e) = getpeerinfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getpeerinfo': {}", e)
                    }
                if !args.disable_getmempoolinfo
                    && let Err(e) = getmempoolinfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getmempoolinfo': {}", e)
                    }
                if !args.disable_uptime
                    && let Err(e) = uptime(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'uptime': {}", e)
                    }
                if !args.disable_getnettotals
                    && let Err(e) = getnettotals(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getnettotals': {}", e)
                    }
                if !args.disable_getmemoryinfo
                    && let Err(e) = getmemoryinfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getmemoryinfo': {}", e)
                    }
                if !args.disable_getaddrmaninfo
                    && let Err(e) = getaddrmaninfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getaddrmaninfo': {}", e)
                    }
                if !args.disable_getnetworkinfo
                    && let Err(e) = getnetworkinfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getnetworkinfo': {}", e)
                }
                if !args.disable_getorphantxs
                    && let Err(e) = getorphantxs(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getorphantxs': {}", e)
                }
                if !args.disable_estimatesmartfee
                    && let Err(e) = estimatesmartfee(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'estimatesmartfee': {}", e)
                }
            }
            _ = less_frequent_interval.tick() => {
                // make sure to update the Args docs when changing these:
                if !args.disable_getchaintxstats
                    && let Err(e) = getchaintxstats(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getchaintxstats': {}", e)
                }
                if !args.disable_getblockchaininfo
                    && let Err(e) = getblockchaininfo(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getblockchaininfo': {}", e)
                }
                if !args.disable_getrawaddrman
                    && let Err(e) = getrawaddrman(&rpc_client, &nats_client, &metrics).await {
                        log::error!("Could not fetch and publish 'getrawaddrman': {}", e)
                }
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

async fn getpeerinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let peer_info = measure_rpc_call("getpeerinfo", metrics, || rpc_client.get_peer_info())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::PeerInfos(peer_info.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getpeerinfo"])
                .inc();
        })?;
    Ok(())
}

async fn getmempoolinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let mempool_info =
        measure_rpc_call("getmempoolinfo", metrics, || rpc_client.get_mempool_info())?
            .into_model()?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::MempoolInfo(
            mempool_info.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getmempoolinfo"])
                .inc();
        })?;
    Ok(())
}

async fn uptime(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let uptime_seconds = measure_rpc_call("uptime", metrics, || rpc_client.uptime())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::Uptime(uptime_seconds)),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["uptime"])
                .inc();
        })?;
    Ok(())
}

async fn getnettotals(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let net_totals = measure_rpc_call("getnettotals", metrics, || rpc_client.get_net_totals())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::NetTotals(net_totals.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getnettotals"])
                .inc();
        })?;
    Ok(())
}

async fn getmemoryinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let memory_info = measure_rpc_call("getmemoryinfo", metrics, || rpc_client.get_memory_info())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::MemoryInfo(memory_info.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getmemoryinfo"])
                .inc();
        })?;
    Ok(())
}

async fn getaddrmaninfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let addrman_info =
        measure_rpc_call("getaddrmaninfo", metrics, || rpc_client.get_addr_man_info())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::AddrmanInfo(
            addrman_info.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getaddrmaninfo"])
                .inc();
        })?;
    Ok(())
}

async fn getchaintxstats(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let chain_tx_stats: GetChainTxStats = measure_rpc_call("getchaintxstats", metrics, || {
        rpc_client.get_chain_tx_stats()
    })?
    .into_model()?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::ChainTxStats(
            chain_tx_stats.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getchaintxstats"])
                .inc();
        })?;
    Ok(())
}

async fn getnetworkinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let network_info: GetNetworkInfo =
        measure_rpc_call("getnetworkinfo", metrics, || rpc_client.get_network_info())?
            .into_model()?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::NetworkInfo(
            network_info.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getnetworkinfo"])
                .inc();
        })?;
    Ok(())
}

async fn getblockchaininfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let blockchain_info: GetBlockchainInfo =
        measure_rpc_call("getblockchaininfo", metrics, || {
            rpc_client.get_blockchain_info()
        })?
        .into_model()?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::BlockchainInfo(
            blockchain_info.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getblockchaininfo"])
                .inc();
        })?;
    Ok(())
}

async fn getorphantxs(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let orphans: GetOrphanTxsVerboseTwo = measure_rpc_call("getorphantxs", metrics, || {
        rpc_client.get_orphan_txs_verbosity_2()
    })?
    .into_model()?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::OrphanTxs(orphans.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getorphantxs"])
                .inc();
        })?;
    Ok(())
}

async fn getrawaddrman(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    let addrman = measure_rpc_call("getrawaddrman", metrics, || rpc_client.get_raw_addrman())?;

    let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc_extractor::rpc::RpcEvent::Addrman(addrman.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await
        .inspect_err(|_| {
            metrics
                .nats_publish_errors
                .with_label_values(&["getrawaddrman"])
                .inc();
        })?;
    Ok(())
}

async fn estimatesmartfee(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
    metrics: &Metrics,
) -> Result<(), FetchOrPublishError> {
    const BLOCKS_10MIN: u32 = 1;
    const BLOCKS_1HOUR: u32 = 6;
    const BLOCKS_1DAY: u32 = 144;
    const BLOCK_TARGETS: [u32; 3] = [BLOCKS_10MIN, BLOCKS_1HOUR, BLOCKS_1DAY];

    const MODES: [FeeEstimateMode; 2] =
        [FeeEstimateMode::Economical, FeeEstimateMode::Conservative];

    for target in BLOCK_TARGETS {
        for mode in MODES {
            let estimate = measure_rpc_call("estimatesmartfee", metrics, || {
                rpc_client.estimate_smart_fee_with_mode(target, mode)
            })?;
            let estimate = estimate.into_model().unwrap();

            let proto = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
                rpc_event: Some(rpc_extractor::rpc::RpcEvent::EstimateSmartFee(
                    EstimateSmartFee::from_rpc(estimate, target, mode.into()),
                )),
            }))?;

            nats_client
                .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
                .await
                .inspect_err(|_| {
                    metrics
                        .nats_publish_errors
                        .with_label_values(&["estimatesmartfee"])
                        .inc();
                })?;
        }
    }

    Ok(())
}
