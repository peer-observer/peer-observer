#![cfg(feature = "nats_integration_tests")]

use logger::{error::RuntimeError, Args};

use shared::{
    log::{self, Level, Record, SetLoggerError},
    nats_subjects::Subject,
    prost::Message,
    protobuf::{
        ebpf_extractor::{
            addrman::{self, InsertNew, InsertTried},
            ebpf,
            mempool::{self, Added},
            net_conn::{self, Connection, InboundConnection},
            net_msg::{self, message::Msg, Metadata, Ping, Pong},
            validation::{self, BlockConnected},
            Ebpf,
        },
        event_msg::{event_msg::Event, EventMsg},
        log_extractor::{self, LogDebugCategory},
        p2p_extractor,
        rpc_extractor::{self, PeerInfo, PeerInfos},
    },
    testing::{nats_publisher::NatsPublisherForTesting, nats_server::NatsServerForTesting},
    tokio::{self, sync::watch, time::sleep},
};

use std::{
    collections::HashMap,
    sync::{Mutex as StdMutex, Once},
    time::Duration,
};

static INIT: Once = Once::new();
static LOGGER: TestLogger = TestLogger;
static LOGS: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

struct TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        println!("TestLogger: {}", record.args());
        if self.enabled(record.metadata()) {
            let mut logs = LOGS.lock().unwrap();
            logs.push(format!("{}", record.args()));
        }
    }

    fn flush(&self) {}
}

fn init_logger() -> Result<(), SetLoggerError> {
    INIT.call_once(|| {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);
    });
    Ok(())
}

pub fn get_logged_messages() -> Vec<String> {
    LOGS.lock().unwrap().clone()
}

fn make_test_args(
    nats_port: u16,
    messages: bool,
    connections: bool,
    addrman: bool,
    mempool: bool,
    validation: bool,
    rpc: bool,
    p2p_extractor: bool,
    log_extractor: bool,
) -> Args {
    Args::new(
        format!("127.0.0.1:{}", nats_port),
        log::Level::Trace,
        messages,
        connections,
        addrman,
        mempool,
        validation,
        rpc,
        p2p_extractor,
        log_extractor,
    )
}

fn check_logs(expected: &[&str]) -> Result<bool, std::io::Error> {
    let logs = get_logged_messages();

    let mut no_lines_missing = true;
    for line in expected {
        let line = line.trim();
        if line == "" {
            continue;
        }
        if !logs.contains(&String::from(line)) {
            println!("log does not contain line: '{}'", line);
            no_lines_missing = false;
        }
    }
    return Ok(no_lines_missing);
}

async fn publish_and_check(events: &[EventMsg], subject: Subject, expected: &str) {
    init_logger().unwrap();

    let nats_server = NatsServerForTesting::new().await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let logger_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
        );
        logger::run(args, shutdown_rx.clone()).await.unwrap();
    });
    // allow the logger tool to start
    sleep(Duration::from_secs(1)).await;

    for event in events {
        log::debug!("publishing: {:?}", event);
        nats_publisher
            .publish(subject.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(100)).await;

    let expected_lines: Vec<&str> = expected.split('\n').collect();
    assert!(check_logs(&expected_lines).expect("Could not check logs"));

    shutdown_tx.send(true).unwrap();
    logger_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_logger_basic() {
    println!("test that we can connect to NATS");

    publish_and_check(
        &[],
        Subject::NetMsg, // not used
        "",
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_fail_if_no_nats() {
    init_logger().unwrap();
    println!("test that we fail if we can't connect to NATS");

    let (_, shutdown_rx) = watch::channel(false);
    let logger_handle = tokio::spawn(async move {
        let args = make_test_args(
            65535, // There shouln't be a NATS server running on this port..
            true, true, true, true, true, true, true, true,
        );
        match logger::run(args, shutdown_rx.clone()).await {
            Ok(_) => panic!("We should fail when no NATS server is reachable."),
            Err(e) => match e {
                RuntimeError::NatsConnect(_) => (),
                _ => panic!("Expected NatsConnect error since the NATS server isn't reachable."),
            },
        };
    });

    logger_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_logger_p2p_messages() {
    println!("test that P2P messages are logged");

    publish_and_check(
        &[
            EventMsg::new(Event::EbpfExtractor(Ebpf {
                event: Some(ebpf::Event::Msg(net_msg::Message {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1336 })),
                })),
            }))
            .unwrap(),
            EventMsg::new(Event::EbpfExtractor(Ebpf {
                event: Some(ebpf::Event::Msg(net_msg::Message {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "pong".to_string(),
                        inbound: false,
                        size: 8,
                    },
                    msg: Some(Msg::Pong(Pong { value: 1337 })),
                })),
            }))
            .unwrap(),
        ],
        Subject::NetMsg,
        r#"
        message: inbound from id=0 (conn_type=1): Ping(1336)
        message: outbound to id=0 (conn_type=1): Pong(1337)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_connections() {
    println!("test that connections are logged");

    publish_and_check(
        &[EventMsg::new(Event::EbpfExtractor(Ebpf {
            event: Some(ebpf::Event::Conn(net_conn::ConnectionEvent {
                event: Some(net_conn::connection_event::Event::Inbound(
                    InboundConnection {
                        conn: Connection {
                            addr: "127.0.0.1:8333".to_string(),
                            conn_type: 1,
                            network: 2,
                            peer_id: 7,
                        },
                        existing_connections: 123,
                    },
                )),
            })),
        }))
        .unwrap()],
        Subject::NetConn,
        r#"
        connection: InboundConnection(conn=Connection(id=7, addr=127.0.0.1:8333, conn_type=1, network=2), existing_connections=123)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_validation() {
    println!("test that validation events are logged");

    publish_and_check(
        &[EventMsg::new(Event::EbpfExtractor(Ebpf {
            event: Some(ebpf::Event::Validation(validation::ValidationEvent {
                event: Some(validation::validation_event::Event::BlockConnected(
                    BlockConnected {
                        hash: vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
                        height: 1337,
                        transactions: 13,
                        inputs: 3,
                        sigops: 7,
                        connection_time: 5000,
                    },
                )),
            })),
        })).unwrap()],
        Subject::Validation,
        r#"
        validation: BlockConnected(hash=1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100, height=1337, transactions=13, inputs=3, sigops=7, time=5000ns)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_mempool_added() {
    println!("test that mempool events are logged");

    publish_and_check(
        &[EventMsg::new(Event::EbpfExtractor(Ebpf {
            event: Some(ebpf::Event::Mempool(mempool::MempoolEvent {
                event: Some(mempool::mempool_event::Event::Added(Added {
                    fee: 123,
                    txid: vec![
                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                        22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                    ],
                    vsize: 453,
                })),
            }))
        }))
        .unwrap()],
        Subject::Mempool,
        r#"
        mempool: Added(1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100, fee=123, vsize=453)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_rpc_peerinfo() {
    println!("test that RPC events are logged");

    publish_and_check(
        &[EventMsg::new(Event::RpcExtractor(rpc_extractor::Rpc {
            event: Some(rpc_extractor::rpc::Event::PeerInfos(PeerInfos {
                infos: vec![
                    PeerInfo {
                        addr_processed: 1234,
                        addr_rate_limited: 1234,
                        addr_relay_enabled: false,
                        // a random IP belonging to a tor exit node.
                        // This might not be a tor exit node IP in the future and the IP would need to updated.
                        address: "179.43.182.232:1234".to_string(),
                        address_bind: "1.2.3.4:8332".to_string(),
                        address_local: "1.2.3.4:8332".to_string(),
                        bip152_hb_from: true,
                        bip152_hb_to: false,
                        bytes_received: 1,
                        bytes_received_per_message: HashMap::new(),
                        bytes_sent_per_message: HashMap::new(),
                        bytes_sent: 0,
                        connection_time: 1,
                        connection_type: "type0".to_string(),
                        id: 1,
                        inbound: true,
                        inflight: vec![1337, 45324],
                        last_block: 1337,
                        last_received: 1234,
                        last_send: 1234,
                        last_transaction: 1234,
                        mapped_as: 1234,
                        minfeefilter: 1234.0,
                        minimum_ping: 1234.0,
                        network: "ipv4".to_string(),
                        permissions: vec!["permission".to_string()],
                        ping_time: 1234.0,
                        ping_wait: 1234.0,
                        relay_transactions: true,
                        services: "service".to_string(),
                        starting_height: 1337,
                        subversion: "subversion".to_string(),
                        synced_blocks: 4,
                        synced_headers: 5,
                        time_offset: 1234,
                        transport_protocol_type: "v1".to_string(),
                        version: 2841,
                        cpu_load: 0.0,
                        inv_to_send: 0,
                    },
                    PeerInfo {
                        addr_processed: 342,
                        addr_rate_limited: 0,
                        addr_relay_enabled: true,
                        address: "162.218.65.123:8332".to_string(), // LinkingLion IP
                        address_bind: "1.2.3.4:8332".to_string(),
                        address_local: "1.2.3.4:8332".to_string(),
                        bip152_hb_from: false,
                        bip152_hb_to: true,
                        bytes_received: 2344,
                        bytes_received_per_message: HashMap::new(),
                        bytes_sent_per_message: HashMap::new(),
                        bytes_sent: 3483,
                        connection_time: 8432,
                        connection_type: "type1".to_string(),
                        id: 2,
                        inbound: false,
                        inflight: vec![],
                        last_block: 1337,
                        last_received: 1234,
                        last_send: 1234,
                        last_transaction: 1234,
                        mapped_as: 0,
                        minfeefilter: 2.0,
                        minimum_ping: 13.0,
                        network: "ipv6".to_string(),
                        permissions: vec!["permission".to_string()],
                        ping_time: 23.0,
                        ping_wait: 53.0,
                        relay_transactions: false,
                        services: "service".to_string(),
                        starting_height: 231,
                        subversion: "subversion2".to_string(),
                        synced_blocks: 4,
                        synced_headers: 5,
                        time_offset: -1239,
                        transport_protocol_type: "v2".to_string(),
                        version: 2342,
                        cpu_load: 0.0,
                        inv_to_send: 0,
                    },
                    PeerInfo {
                        addr_processed: 342,
                        addr_rate_limited: 434,
                        addr_relay_enabled: true,
                        address: "162.218.65.123:8332".to_string(), // LinkingLion IP
                        address_bind: "1.2.3.4:8332".to_string(),
                        address_local: "1.2.3.4:8332".to_string(),
                        bip152_hb_from: false,
                        bip152_hb_to: true,
                        bytes_received: 2344,
                        bytes_received_per_message: HashMap::new(),
                        bytes_sent_per_message: HashMap::new(),
                        bytes_sent: 3483,
                        connection_time: 8432,
                        connection_type: "type1".to_string(),
                        id: 2,
                        inbound: false,
                        inflight: vec![],
                        last_block: 1337,
                        last_received: 1234,
                        last_send: 1234,
                        last_transaction: 1234,
                        mapped_as: 1234,
                        minfeefilter: 2.0,
                        minimum_ping: 13.0,
                        network: "ipv6".to_string(),
                        permissions: vec!["permission".to_string()],
                        ping_time: 23.0,
                        ping_wait: 53.0,
                        relay_transactions: false,
                        services: "service".to_string(),
                        starting_height: 231,
                        subversion: "subversion2".to_string(),
                        synced_blocks: 4,
                        synced_headers: 5,
                        time_offset: -1239,
                        transport_protocol_type: "v2".to_string(),
                        version: 2342,
                        cpu_load: 0.0,
                        inv_to_send: 0,
                    },
                ],
            })),
        }))
        .unwrap()],
        Subject::Rpc,
        r#"
        rpc: PeerInfos([PeerInfo(id=1), PeerInfo(id=2), PeerInfo(id=2)])
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_addrman() {
    println!("test that addrman events are logged");

    publish_and_check(
        &[EventMsg::new(Event::EbpfExtractor(Ebpf {
            event: Some(ebpf::Event::Addrman(addrman::AddrmanEvent {
                event: Some(addrman::addrman_event::Event::New(InsertNew {
                    addr: "127.0.0.1:2340".to_string(),
                    addr_as: 2,
                    bucket: 2,
                    bucket_pos: 2,
                    inserted: false,
                    source: "127.0.0.1:2340".to_string(),
                    source_as: 0,
                })),
            })),
        })).unwrap(),
        EventMsg::new(Event::EbpfExtractor(Ebpf {
            event: Some(ebpf::Event::Addrman(addrman::AddrmanEvent {
                event: Some(addrman::addrman_event::Event::Tried(InsertTried {
                    addr: "127.0.0.1:2340".to_string(),
                    addr_as: 2,
                    bucket: 2,
                    bucket_pos: 2,
                    source: "127.0.0.1:2340".to_string(),
                    source_as: 0,
                })),
            })),
        })).unwrap(),
        ],
        Subject::Addrman,
        r#"
        addrman: InsertNew(inserted=false, bucket=2, bucket_pos=2, addr=127.0.0.1:2340, addr_AS=2, source=127.0.0.1:2340, source_AS=0)
        addrman: InsertTried(bucket=2, bucket_pos=2, addr=127.0.0.1:2340, addr_AS=2, source=127.0.0.1:2340, source_AS=0)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_p2pextractor_ping_duration() {
    println!("test that p2p-extractor events are logged");

    publish_and_check(
        &[EventMsg::new(Event::P2pExtractor(p2p_extractor::P2p {
            event: Some(p2p_extractor::p2p::Event::PingDuration(
                p2p_extractor::PingDuration { duration: 1234567 },
            )),
        }))
        .unwrap()],
        Subject::Validation,
        r#"
        p2p event: PingDuration(1234567ns)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_logextractor_unknown_log() {
    println!("test that log-extractor unknown events are logged");

    publish_and_check(
        &[EventMsg::new(Event::LogExtractor(log_extractor::Log {
            category: LogDebugCategory::Unknown.into(),
            log_timestamp: 1234,
            event: Some(log_extractor::log::Event::UnknownLogMessage(
                log_extractor::UnknownLogMessage {
                    raw_message: "test".to_string(),
                },
            )),
        }))
        .unwrap()],
        Subject::LogExtractor,
        r#"
        log event: 1234 [unknown] UnknownLogMessage(test)
        "#,
    )
    .await;
}

#[tokio::test]
async fn test_integration_logger_logextractor_blockconnected_log() {
    println!("test that log-extractor BlockConnected events are logged");

    publish_and_check(
        &[
            EventMsg::new(Event::LogExtractor(log_extractor::Log {
                category: LogDebugCategory::Validation.into(),
                log_timestamp: 345,
                event: Some(log_extractor::log::Event::BlockConnectedLog(
                    log_extractor::BlockConnectedLog {
                        block_height: 1337,
                        block_hash:
                            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string(),
                    },
                )),
            }))
            .unwrap(),
        ],
        Subject::LogExtractor,
        r#"
        log event: 345 [validation] BlockConnected(hash=000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, height=1337)
        "#,
    )
    .await;
}
