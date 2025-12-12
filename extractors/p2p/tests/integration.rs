#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use shared::{
    async_nats,
    bitcoin::{self, Amount},
    corepc_node::{self},
    futures::StreamExt,
    log::{self, info},
    prost::Message,
    protobuf::{
        bitcoin_primitives::inventory_item::Item,
        event::{Event, event::PeerObserverEvent},
        p2p_extractor::p2p::P2pEvent::{
            AddressAnnouncement, FeefilterAnnouncement, InventoryAnnouncement, PingDuration,
        },
    },
    rand::{self, Rng},
    simple_logger::SimpleLogger,
    testing::nats_server::NatsServerForTesting,
    tokio::{
        self,
        sync::watch,
        time::{Duration, sleep},
    },
    util,
};
use std::str::FromStr;
use std::sync::{
    Once, OnceLock,
    atomic::{AtomicU16, Ordering},
};

use p2p_extractor::{Args, Network};

static INIT: Once = Once::new();
static NEXT_P2PEXTRACTOR_PORT: OnceLock<AtomicU16> = OnceLock::new();

// 1 second ping interval for fast tests
const PING_INTERVAL_SECONDS: u64 = 1;

fn setup() -> u16 {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();

        let mut rng = rand::rng();

        // choose start ports from the ephemeral port range
        let p2p_extractor_start = rng.random_range(49152..65500);
        NEXT_P2PEXTRACTOR_PORT
            .set(AtomicU16::new(p2p_extractor_start))
            .unwrap();
    });
    let p2p_extractor_port = NEXT_P2PEXTRACTOR_PORT
        .get()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    p2p_extractor_port
}

fn make_test_args(
    nats_port: u16,
    p2p_address: String,
    disable_ping: bool,
    disable_addrv2: bool,
    disable_invs: bool,
    disable_feefilter: bool,
) -> Args {
    Args::new(
        format!("127.0.0.1:{}", nats_port),
        log::Level::Trace,
        p2p_address,
        Network::Regtest,
        PING_INTERVAL_SECONDS,
        disable_ping,
        disable_addrv2,
        disable_invs,
        disable_feefilter,
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

fn setup_node_with_addnode(p2p_extractor_port: u16) -> corepc_node::Node {
    let mut node_conf = corepc_node::Conf::default();
    let addnode = format!("--addnode=127.0.0.1:{}", p2p_extractor_port);
    node_conf.args = vec![
        "-regtest",
        "-debug=net",
        "-debug=rpc",
        // we don't want the node to connect to any IPs we might send it during
        // our testing.
        "-connect=0",
        "-listen=1",
        "-fallbackfee=0.0000001",
        &addnode,
    ];
    // enabling this is useful for debugging, but enabling this by default will
    // be quite spammy.
    node_conf.view_stdout = false;
    node_conf.p2p = corepc_node::P2P::Yes;
    let node = setup_node(node_conf);

    node
}

async fn check(
    disable_ping: bool,
    disable_addrv2: bool,
    disable_invs: bool,
    disable_feefilter: bool,
    test_setup: fn(&corepc_node::Node),
    check_expected: fn(PeerObserverEvent) -> bool,
) {
    let p2p_extractor_port = setup();
    let nats_server = NatsServerForTesting::new().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let p2p_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            format!("127.0.0.1:{}", p2p_extractor_port),
            disable_ping,
            disable_addrv2,
            disable_invs,
            disable_feefilter,
        );
        p2p_extractor::run(args, shutdown_rx.clone())
            .await
            .expect("p2p-extractor failed");
    });

    // allow the p2p-extractor to start
    sleep(Duration::from_secs(2)).await;

    // only start the node after the P2P extractor to make sure the
    // extractor is ready to accept connections
    let node = setup_node_with_addnode(p2p_extractor_port);

    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
        .await
        .unwrap();
    let mut sub = nc.subscribe("*").await.unwrap();

    // Make sure the p2p-extractor and node are connected
    let mut connected = false;
    for i in 0..100 {
        let peers = node.client.get_peer_info().unwrap().0;
        if peers.len() == 1 {
            if peers[0].transport_protocol_type == "v1" {
                log::info!("p2p-extractor and node are connected: {:?}", peers[0]);
                connected = true;
                break;
            }
        }
        log::warn!(
            "p2p-extractor and node are not yet connected: attempt {}",
            i
        );
        sleep(Duration::from_secs(1)).await;
    }
    assert!(connected, "The node and p2p-extractor aren't conencted.");

    sleep(Duration::from_secs(1)).await;
    test_setup(&node);
    sleep(Duration::from_secs(1)).await;

    while let Some(msg) = sub.next().await {
        let unwrapped = Event::decode(msg.payload).unwrap();
        if let Some(event) = unwrapped.peer_observer_event {
            if check_expected(event) {
                break;
            }
        }
    }

    shutdown_tx.send(true).unwrap();
    p2p_extractor_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_p2pextractor_ping_measurements() {
    println!("test that we receive Ping measurement P2P-extractor events");

    check(
        false,
        true,
        true,
        true,
        |_| (),
        |event| {
            match event {
                PeerObserverEvent::P2pExtractor(p) => {
                    if let Some(ref e) = p.p2p_event {
                        match e {
                            PingDuration(p) => {
                                // we expect the duration to be >0ns
                                assert!(p.duration > 0);
                                return true;
                            }
                            _ => {
                                log::info!("unexpected P2P extractor event {:?}", p.p2p_event);
                                return true;
                            }
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            }
            return false;
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_p2pextractor_addr_annoucement() {
    println!("test that we receive AddressAnnouncement P2P-extractor events");

    check(
        true,
        false,
        true,
        true,
        |node| {
            // To self-announce our address, we need to be out ouf initial block download
            // Mine a block to get out of initial block download
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();
            node.client.generate_to_address(1, &address).unwrap();
            assert_eq!(
                false,
                node.client
                    .get_blockchain_info()
                    .unwrap()
                    .initial_block_download
            );

            // Connects to the Bitcoin node, announces one address to it, and disconnect.
            // The node will then relay that address to the p2p-extractor eventually.
            // Do this multiple times to have multiple addresses to relay.
            p2p_client::open_connection_and_send_addr(node.params.p2p_socket.unwrap().port());
            // Move mocktime forward 10min. This makes sure the annoucement is send immediatly and we don't have to wait.
            // HACK: We should use setmocktime directly, but as of writing, it's not implemented in corepc.
            node.client
                .call::<()>(
                    "setmocktime",
                    &[(util::current_timestamp() + 60 * 10).into()],
                )
                .unwrap();
        },
        |event| {
            match event {
                PeerObserverEvent::P2pExtractor(p) => {
                    if let Some(ref e) = p.p2p_event {
                        match e {
                            AddressAnnouncement(a) => {
                                assert!(a.addresses.len() > 0);
                                assert_eq!(a.addresses[0].port, 8333);
                                log::info!("{}", a);
                                return true;
                            }
                            _ => log::info!("unhandled P2P extractor event {:?}", p.p2p_event),
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            }
            return false;
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_p2pextractor_inv_annoucement() {
    println!("test that we receive InventoryAnnouncement P2P-extractor events");

    const NUM_TX: usize = 5;

    check(
        true,
        true,
        false,
        true,
        |node| {
            let address = node
                .client
                .get_new_address(None, None)
                .unwrap()
                .address()
                .unwrap()
                .require_network(bitcoin::Network::Regtest)
                .unwrap();
            node.client.generate_to_address(110, &address).unwrap();
            for _ in 0..NUM_TX {
                node.client
                    .send_to_address(&address, Amount::from_sat(10000))
                    .unwrap();
            }
        },
        |event| {
            match event {
                PeerObserverEvent::P2pExtractor(p) => {
                    if let Some(ref e) = p.p2p_event {
                        match e {
                            InventoryAnnouncement(i) => {
                                log::info!("{}", i);
                                // we expect an inv with NUM_TX from the node, however the node
                                // will also send invs for blocks. So ignore all other invs and
                                // only pass the test on the inv with the size of NUM_TX
                                if i.inventory.len() == NUM_TX {
                                    assert!(i.inventory.iter().all(|inventory| matches!(
                                        inventory.item.clone().unwrap(),
                                        Item::Wtx(_)
                                    )));
                                    return true;
                                }
                            }
                            _ => log::info!("unhandled P2P extractor event {:?}", p.p2p_event),
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            }
            return false;
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_p2pextractor_feefilter_annoucement() {
    println!("test that we receive FeefilterAnnouncement P2P-extractor events");

    check(
        true,
        true,
        true,
        false,
        |_node| {
            // No setup required as the node should automatically send a
            // feefilter message to us right after connecting.
        },
        |event| {
            match event {
                PeerObserverEvent::P2pExtractor(p) => {
                    if let Some(ref e) = p.p2p_event {
                        match e {
                            FeefilterAnnouncement(feefilter) => {
                                log::info!("{}", feefilter);
                                return true;
                            }
                            _ => log::info!("unhandled P2P extractor event {:?}", p.p2p_event),
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            }
            return false;
        },
    )
    .await;
}

mod p2p_client {
    use shared::bitcoin::{
        Network,
        consensus::{Decodable, encode},
        p2p::{
            ServiceFlags,
            address::{self, AddrV2, AddrV2Message},
            message,
            message_network::VersionMessage,
        },
    };
    use shared::rand::Rng;
    use shared::{log, rand, util};

    use std::io::{BufReader, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
    use std::{thread, time};

    const USER_AGENT: &str = "/integration-test/";

    fn build_raw_network_message(payload: message::NetworkMessage) -> message::RawNetworkMessage {
        message::RawNetworkMessage::new(Network::Regtest.magic(), payload)
    }

    // ONLY for the test_integration_p2pextractor_addr_annoucement test
    pub fn open_connection_and_send_addr(port: u16) {
        let version_msg = message::NetworkMessage::Version(VersionMessage::new(
            ServiceFlags::NETWORK_LIMITED,
            util::current_timestamp() as i64,
            address::Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                ServiceFlags::NONE,
            ),
            address::Address::new(
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                ServiceFlags::NONE,
            ),
            rand::rng().random(),
            String::from(USER_AGENT),
            0,
        ));

        if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{}", port)) {
            log::info!("Connection to node opened");
            stream
                .write_all(encode::serialize(&build_raw_network_message(version_msg)).as_slice())
                .unwrap();
            stream.flush().unwrap();
            log::info!("Sent version message");

            // Setup StreamReader
            let read_stream = stream.try_clone().unwrap();
            let mut stream_reader = BufReader::new(read_stream);
            loop {
                let reply =
                    message::RawNetworkMessage::consensus_decode(&mut stream_reader).unwrap();
                match reply.payload() {
                    message::NetworkMessage::Version(_) => {
                        log::info!("Received version message");
                        stream
                            .write_all(
                                encode::serialize(&build_raw_network_message(
                                    message::NetworkMessage::SendAddrV2,
                                ))
                                .as_slice(),
                            )
                            .unwrap();
                        log::info!("Sent sentaddrv2 message");

                        stream
                            .write_all(
                                encode::serialize(&build_raw_network_message(
                                    message::NetworkMessage::Verack,
                                ))
                                .as_slice(),
                            )
                            .unwrap();
                        log::info!("Sent verack message");
                    }
                    message::NetworkMessage::Verack => {
                        log::info!("Received verack message: {:?}", reply.payload());

                        let addr = AddrV2Message {
                            time: util::current_timestamp() as u32,
                            // This address must have "desirable" network flags for the node to process it.
                            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                            port: 8333,
                            addr: AddrV2::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
                        };

                        let addrv2 = message::NetworkMessage::AddrV2(vec![addr]);
                        stream
                            .write_all(
                                encode::serialize(&build_raw_network_message(addrv2.clone()))
                                    .as_slice(),
                            )
                            .unwrap();

                        log::info!("Sent addrv2 message: {:?}", addrv2);

                        // sleep to make sure the address has been processed.
                        thread::sleep(time::Duration::from_secs(1));

                        // disconnect
                        break;
                    }
                    _ => {
                        log::warn!("Received unknown message: {:?}", reply.payload());
                    }
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
        } else {
            eprintln!("failed to open connection");
        }
    }
}
