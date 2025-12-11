use shared::clap::{ArgGroup, Parser};
use shared::corepc_client::client_sync::Auth;
use shared::corepc_client::client_sync::v29::Client;
use shared::log;
use shared::nats_subjects::Subject;
use shared::prost::Message;
use shared::protobuf::event_msg::EventMsg;
use shared::protobuf::event_msg::event_msg::Event;
use shared::protobuf::rpc_extractor;
use shared::tokio::sync::watch;
use shared::tokio::time::{self, Duration};
use shared::{async_nats, clap};

mod error;

use error::{FetchOrPublishError, RuntimeError};

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
    /// Address of the NATS server where the extractor will publish messages to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    pub nats_address: String,

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

    /// Disable quering and publishing of `getpeerinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getpeerinfo: bool,

    /// Disable quering and publishing of `getmempoolinfo` data.
    #[arg(long, default_value_t = false)]
    pub disable_getmempoolinfo: bool,

    /// Disable quering and publishing of `uptime` data.
    #[arg(long, default_value_t = false)]
    pub disable_uptime: bool,

    /// Disable quering and publishing of `getnettotals` data.
    #[arg(long, default_value_t = false)]
    pub disable_getnettotals: bool,
}

impl Args {
    pub fn new(
        nats_address: String,
        log_level: log::Level,
        rpc_host: String,
        rpc_cookie_file: String,
        query_interval: u64,
        disable_getpeerinfo: bool,
        disable_getmempoolinfo: bool,
        disable_uptime: bool,
        disable_getnettotals: bool,
    ) -> Args {
        Self {
            nats_address,
            log_level,
            rpc_host,
            rpc_password: None,
            rpc_user: None,
            rpc_cookie_file: Some(rpc_cookie_file),
            query_interval,
            disable_getpeerinfo,
            disable_getmempoolinfo,
            disable_uptime,
            disable_getnettotals,
            // when adding more disable_* args, make sure to update the disable_all below
        }
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    let auth: Auth = match args.rpc_cookie_file {
        Some(path) => Auth::CookieFile(path.into()),
        None => Auth::UserPass(
            args.rpc_user.expect("need an RPC user"),
            args.rpc_password.expect("need an RPC password"),
        ),
    };
    let rpc_client = Client::new_with_auth(&format!("http://{}", args.rpc_host), auth)?;

    log::debug!("Connecting to NATS server at {}..", args.nats_address);
    let nats_client = async_nats::connect(&args.nats_address).await?;
    log::info!("Connected to NATS server at {}", &args.nats_address);

    let duration_sec = Duration::from_secs(args.query_interval);
    let mut interval = time::interval(duration_sec);
    log::info!(
        "Querying the Bitcoin Core RPC interface every {:?}.",
        duration_sec
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
    // check if we have at least one RPC to query
    let disable_all = args.disable_getpeerinfo
        && args.disable_getmempoolinfo
        && args.disable_uptime
        && args.disable_getnettotals;
    if disable_all {
        log::warn!("No RPC configured to be queried!");
    }

    loop {
        shared::tokio::select! {
            _ = interval.tick() => {
                if !args.disable_getpeerinfo {
                    if let Err(e) = getpeerinfo(&rpc_client, &nats_client).await {
                        log::error!("Could not fetch and publish 'getpeerinfo': {}", e)
                    }
                }
                if !args.disable_getmempoolinfo {
                    if let Err(e) = getmempoolinfo(&rpc_client, &nats_client).await {
                        log::error!("Could not fetch and publish 'getmempoolinfo': {}", e)
                    }
                }
                if !args.disable_uptime {
                    if let Err(e) = uptime(&rpc_client, &nats_client).await {
                        log::error!("Could not fetch and publish 'uptime': {}", e)
                    }
                }
                if !args.disable_getnettotals {
                    if let Err(e) = getnettotals(&rpc_client, &nats_client).await {
                        log::error!("Could not fetch and publish 'getnettotals': {}", e)
                    }
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

async fn getpeerinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
) -> Result<(), FetchOrPublishError> {
    let peer_info = rpc_client.get_peer_info()?;

    let proto = EventMsg::new(Event::Rpc(rpc_extractor::RpcEvent {
        event: Some(rpc_extractor::rpc_event::Event::PeerInfos(peer_info.into())),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await?;
    Ok(())
}

async fn getmempoolinfo(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
) -> Result<(), FetchOrPublishError> {
    let mempool_info = rpc_client.get_mempool_info()?;

    let proto = EventMsg::new(Event::Rpc(rpc_extractor::RpcEvent {
        event: Some(rpc_extractor::rpc_event::Event::MempoolInfo(
            mempool_info.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await?;
    Ok(())
}

async fn uptime(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
) -> Result<(), FetchOrPublishError> {
    let uptime_seconds = rpc_client.uptime()?;

    let proto = EventMsg::new(Event::Rpc(rpc_extractor::RpcEvent {
        event: Some(rpc_extractor::rpc_event::Event::Uptime(uptime_seconds)),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await?;
    Ok(())
}

async fn getnettotals(
    rpc_client: &Client,
    nats_client: &async_nats::Client,
) -> Result<(), FetchOrPublishError> {
    let net_totals = rpc_client.get_net_totals()?;

    let proto = EventMsg::new(Event::Rpc(rpc_extractor::RpcEvent {
        event: Some(rpc_extractor::rpc_event::Event::NetTotals(
            net_totals.into(),
        )),
    }))?;

    nats_client
        .publish(Subject::Rpc.to_string(), proto.encode_to_vec().into())
        .await?;
    Ok(())
}
