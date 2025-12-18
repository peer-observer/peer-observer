#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use shared::{
    async_nats, corepc_node,
    futures::StreamExt,
    log::{self, info},
    prost::Message,
    protobuf::event::{Event, event::PeerObserverEvent},
    protobuf::rpc_extractor::rpc::RpcEvent::{
        AddrmanInfo, ChainTxStats, MemoryInfo, MempoolInfo, NetTotals, PeerInfos, Uptime,
    },
    simple_logger::SimpleLogger,
    testing::nats_server::NatsServerForTesting,
    tokio::{self, sync::watch},
};

use std::sync::Once;

use rpc_extractor::Args;

static INIT: Once = Once::new();

// 1 second query interval for fast tests
const QUERY_INTERVAL_SECONDS: u64 = 1;

fn setup() -> () {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

fn make_test_args(
    nats_port: u16,
    rpc_url: String,
    cookie_file: String,
    disable_getpeerinfo: bool,
    disable_getmempoolinfo: bool,
    disable_uptime: bool,
    disable_getnettotals: bool,
    disable_getmemoryinfo: bool,
    disable_getaddrmaninfo: bool,
    disable_getchaintxstats: bool,
) -> Args {
    Args::new(
        format!("127.0.0.1:{}", nats_port),
        log::Level::Trace,
        rpc_url,
        cookie_file,
        QUERY_INTERVAL_SECONDS,
        disable_getpeerinfo,
        disable_getmempoolinfo,
        disable_uptime,
        disable_getnettotals,
        disable_getmemoryinfo,
        disable_getaddrmaninfo,
        disable_getchaintxstats,
    )
}

fn setup_node(conf: corepc_node::Conf) -> corepc_node::Node {
    info!("env BITCOIND_EXE={:?}", std::env::var("BITCOIND_EXE"));
    info!("exe_path={:?}", corepc_node::exe_path());

    if let Ok(exe_path) = corepc_node::exe_path() {
        info!("Using bitcoind at '{}'", exe_path);
        return corepc_node::Node::with_conf(exe_path, &conf).unwrap();
    }

    info!("Trying to download a bitcoind..");
    return corepc_node::Node::from_downloaded_with_conf(&conf).unwrap();
}

fn setup_two_connected_nodes() -> (corepc_node::Node, corepc_node::Node) {
    // node1 listens for p2p connections
    let mut node1_conf = corepc_node::Conf::default();
    node1_conf.p2p = corepc_node::P2P::Yes;
    let node1 = setup_node(node1_conf);

    // node2 connects to node1
    let mut node2_conf = corepc_node::Conf::default();
    node2_conf.p2p = node1.p2p_connect(true).unwrap();
    let node2 = setup_node(node2_conf);

    (node1, node2)
}

async fn check(
    disable_getpeerinfo: bool,
    disable_getmempoolinfo: bool,
    disable_uptime: bool,
    disable_getnettotals: bool,
    disable_getmemoryinfo: bool,
    disable_getaddrmaninfo: bool,
    disable_getchaintxstats: bool,
    check_expected: fn(PeerObserverEvent) -> (),
) {
    setup();
    let (node1, _node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            node1.rpc_url().replace("http://", ""),
            node1.params.cookie_file.display().to_string(),
            disable_getpeerinfo,
            disable_getmempoolinfo,
            disable_uptime,
            disable_getnettotals,
            disable_getmemoryinfo,
            disable_getaddrmaninfo,
            disable_getchaintxstats,
        );
        rpc_extractor::run(args, shutdown_rx.clone())
            .await
            .expect("rpc extractor failed");
    });

    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
        .await
        .unwrap();
    let mut sub = nc.subscribe("*").await.unwrap();

    while let Some(msg) = sub.next().await {
        let unwrapped = Event::decode(msg.payload).unwrap();
        if let Some(event) = unwrapped.peer_observer_event {
            check_expected(event);
            break;
        }
    }

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_rpc_getpeerinfo() {
    println!("test that we receive getpeerinfo RPC events");

    check(false, true, true, true, true, true, true, |event| {
        match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        PeerInfos(p) => {
                            // we expect 1 peer to be connected
                            assert_eq!(p.infos.len(), 1);
                            let peer = p.infos.first().expect("we have expactly one peer here");
                            assert_eq!(peer.connection_type, "inbound");

                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        }
    })
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getmempoolinfo() {
    println!("test that we receive getmempoolinfo RPC events");

    check(
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        MempoolInfo(info) => {
                            assert_eq!(info.loaded, true);
                            assert_eq!(info.size, 0);
                            assert_eq!(info.usage, 0);
                            assert_eq!(info.bytes, 0);
                            assert_eq!(info.total_fee, 0.0);
                            assert_eq!(info.max_mempool, 300000000);
                            // These will change between v29 and v30, so don't hardcode something here.
                            assert!(info.mempoolminfee > 0.0);
                            assert!(info.minrelaytxfee > 0.0);
                            assert!(info.incrementalrelayfee > 0.0);

                            assert_eq!(info.unbroadcastcount, 0);
                            assert_eq!(info.fullrbf, true);
                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_uptime() {
    println!("test that we receive uptime RPC events");

    check(
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        Uptime(uptime_seconds) => {
                            // Uptime should be a positive number
                            assert!(*uptime_seconds > 0);
                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getnettotals() {
    println!("test that we receive getnettotals RPC events");

    check(
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        NetTotals(net_totals) => {
                            assert!(net_totals.time_millis > 0);
                            assert!(net_totals.total_bytes_received > 0);
                            assert!(net_totals.total_bytes_sent > 0);
                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getmemoryinfo() {
    println!("test that we receive getmemoryinfo RPC events");

    check(
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        MemoryInfo(info) => {
                            assert!(info.total > 0);
                            assert!(info.used <= info.total);
                            assert!(info.locked <= info.total);
                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getaddrmaninfo() {
    println!("test that we receive getaddrmaninfo RPC events");

    check(
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        AddrmanInfo(info) => {
                            assert!(!info.networks.is_empty());

                            if let Some(all_nets) = info.networks.get("all_networks") {
                                assert_eq!(
                                    all_nets.total,
                                    all_nets.new + all_nets.tried,
                                    "all_networks: total should equal new + tried"
                                );
                            }

                            for (network, data) in &info.networks {
                                assert_eq!(
                                    data.total,
                                    data.new + data.tried,
                                    "Network {}: total should equal new + tried",
                                    network
                                );
                            }

                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getchaintxstats() {
    println!("test that we receive getchaintxstats RPC events");

    check(
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        ChainTxStats(stats) => {
                            assert!(stats.time > 0);
                            assert!(stats.tx_count > 0);
                            assert!(!stats.window_final_block_hash.is_empty());
                            assert!(stats.window_final_block_height >= 0);
                            assert!(stats.window_block_count >= 0);
                            // Note: window_tx_count, window_interval, and tx_rate
                            // are only present when window_block_count > 0, which
                            // requires mined blocks. Fresh regtest has 0 blocks.
                            return;
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}
