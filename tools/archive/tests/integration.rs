#![cfg(feature = "nats_integration_tests")]

use archive::archiver::{run, Args, DRAIN_TIMEOUT};

use archive::read::ArchiveReader;
use shared::{
    log,
    nats_subjects::Subject,
    nats_util,
    prost::Message,
    protobuf::{
        bitcoin_primitives,
        ebpf_extractor::{
            connection::{self, Connection, InboundConnection},
            ebpf,
            mempool::{self, Added},
            message::{self, message_event::Msg, Metadata, Ping},
            validation::{self, BlockConnected},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
        ipc_extractor::{self, BlockTip},
        log_extractor::{self, LogDebugCategory},
        p2p_extractor, rpc_extractor,
    },
    simple_logger,
    testing::{nats_publisher::NatsPublisherForTesting, nats_server::NatsServerForTesting},
    tokio::{
        self,
        sync::{oneshot, watch},
        task::JoinHandle,
        time::sleep,
    },
};
use std::{
    sync::Once,
    time::{Duration, Instant},
};

static INIT: Once = Once::new();

fn find_files(dir: &std::path::Path, suffix: &str) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(suffix))
        .map(|e| e.path())
        .collect()
}

fn setup() {
    INIT.call_once(|| {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

fn make_test_args(nats_port: u16, output_dir: &std::path::Path) -> Args {
    Args {
        nats: nats_util::NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        output_dir: output_dir.to_path_buf(),
        base_name: "test".to_string(),
        max_file_size: 104_857_600,
        log_level: log::Level::Info,
        messages: false,
        connections: false,
        mempool: false,
        validation: false,
        rpc: false,
        p2p_extractor: false,
        log_extractor: false,
        ipc_extractor: false,
        compression_level: 3,
        low_data: false,
    }
}

fn make_all_event_types() -> Vec<(Event, &'static str)> {
    let events = vec![
        // 1. ebpf message
        (
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1337 })),
                })),
            }))
            .unwrap(),
            "messages",
        ),
        // 2. ebpf connection
        (
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                    event: Some(connection::connection_event::Event::Inbound(
                        InboundConnection {
                            conn: Connection {
                                addr: "127.0.0.1:8333".to_string(),
                                conn_type: 1,
                                network: 1,
                                peer_id: 1,
                            },
                            existing_connections: 10,
                        },
                    )),
                })),
            }))
            .unwrap(),
            "connections",
        ),
        // 3. ebpf mempool
        (
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
                    event: Some(mempool::mempool_event::Event::Added(Added {
                        txid: vec![0u8; 32],
                        vsize: 250,
                        fee: 1000,
                    })),
                })),
            }))
            .unwrap(),
            "mempool",
        ),
        // 5. ebpf validation
        (
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Validation(validation::ValidationEvent {
                    event: Some(validation::validation_event::Event::BlockConnected(
                        BlockConnected {
                            hash: vec![0u8; 32],
                            height: 800000,
                            transactions: 3000,
                            inputs: 5000,
                            sigops: 10000,
                            connection_time: 500000,
                        },
                    )),
                })),
            }))
            .unwrap(),
            "validation",
        ),
        // 6. rpc
        (
            Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
                rpc_event: Some(rpc_extractor::rpc::RpcEvent::Uptime(12345)),
            }))
            .unwrap(),
            "rpc",
        ),
        // 7. p2p_extractor
        (
            Event::new(PeerObserverEvent::P2pExtractor(p2p_extractor::P2p {
                p2p_event: Some(p2p_extractor::p2p::P2pEvent::PingDuration(
                    p2p_extractor::PingDuration { duration: 500000 },
                )),
            }))
            .unwrap(),
            "p2p_extractor",
        ),
        // 8. log_extractor
        (
            Event::new(PeerObserverEvent::LogExtractor(log_extractor::Log {
                category: LogDebugCategory::Unknown.into(),
                log_timestamp: 1234,
                threadname: String::new(),
                log_level: log_extractor::LogLevel::Info.into(),
                log_line_bytes: 8,
                log_event: Some(log_extractor::log::LogEvent::UnknownLogMessage(
                    log_extractor::UnknownLogMessage {
                        raw_message: "test log".to_string(),
                    },
                )),
            }))
            .unwrap(),
            "log_extractor",
        ),
        // 9. ipc_extractor
        (
            Event::new(PeerObserverEvent::IpcExtractor(ipc_extractor::Ipc {
                ipc_event: Some(ipc_extractor::ipc::IpcEvent::BlockTip(BlockTip {
                    height: 0,
                    hash: vec![0u8; 32],
                })),
            }))
            .unwrap(),
            "ipc_extractor",
        ),
    ];

    // Compile-time check: if a new PeerObserverEvent variant is added,
    // this match becomes non-exhaustive and fails to compile.
    match events[0].0.peer_observer_event.as_ref().unwrap() {
        PeerObserverEvent::EbpfExtractor(e) => match e.ebpf_event.as_ref().unwrap() {
            ebpf::EbpfEvent::Message(_) => (),
            ebpf::EbpfEvent::Connection(_) => (),
            ebpf::EbpfEvent::Mempool(_) => (),
            ebpf::EbpfEvent::Validation(_) => (),
        },
        PeerObserverEvent::RpcExtractor(_) => (),
        PeerObserverEvent::P2pExtractor(_) => (),
        PeerObserverEvent::LogExtractor(_) => (),
        PeerObserverEvent::IpcExtractor(_) => (),
    }

    events
}

async fn wait_for_archiver_ready(
    ready_rx: oneshot::Receiver<()>,
    archiver_handle: &mut JoinHandle<()>,
) {
    tokio::select! {
        result = ready_rx => result.expect("archiver should send readiness signal"),
        result = archiver_handle => {
            result.unwrap();
            unreachable!("archiver task exited before sending readiness signal");
        }
        _ = sleep(Duration::from_secs(5)) => {
            panic!("timed out waiting for archiver readiness signal");
        }
    }
}

async fn run_filter_test(flag: &str, expected_count: usize) {
    setup();

    let tmp_dir = std::env::temp_dir().join(format!("archiver_test_{}", flag));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let flag_owned = flag.to_string();
    let mut archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        match flag_owned.as_str() {
            "messages" => args.messages = true,
            "connections" => args.connections = true,
            "mempool" => args.mempool = true,
            "validation" => args.validation = true,
            "rpc" => args.rpc = true,
            "p2p_extractor" => args.p2p_extractor = true,
            "log_extractor" => args.log_extractor = true,
            "ipc_extractor" => args.ipc_extractor = true,
            _ => {} // archive_all
        }
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let all_events = make_all_event_types();
    for (event, _label) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin.zst")
        .into_iter()
        .next()
        .expect("expected a .<timestamp>.bin.zst file");

    let archive = ArchiveReader::open(&archive_path).unwrap();
    assert_eq!(archive.count(), expected_count);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn test_filter_all() {
    run_filter_test("all", 8).await;
}

#[tokio::test]
async fn test_filter_messages() {
    run_filter_test("messages", 1).await;
}

#[tokio::test]
async fn test_filter_connections() {
    run_filter_test("connections", 1).await;
}

#[tokio::test]
async fn test_filter_mempool() {
    run_filter_test("mempool", 1).await;
}

#[tokio::test]
async fn test_filter_validation() {
    run_filter_test("validation", 1).await;
}

#[tokio::test]
async fn test_filter_rpc() {
    run_filter_test("rpc", 1).await;
}

#[tokio::test]
async fn test_filter_p2p_extractor() {
    run_filter_test("p2p_extractor", 1).await;
}

#[tokio::test]
async fn test_filter_log_extractor() {
    run_filter_test("log_extractor", 1).await;
}

#[tokio::test]
async fn test_filter_ipc() {
    run_filter_test("ipc_extractor", 1).await;
}

#[tokio::test]
async fn test_file_rotation_with_compression() {
    setup();

    let tmp_dir = std::env::temp_dir().join("archiver_test_rotation_with_compression");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let mut archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.max_file_size = 1; // force rotation on every event
        args.compression_level = 1;
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let all_events = make_all_event_types();
    for (event, _label) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    // count how many .bin.zst files were created
    let zst_files: Vec<_> = std::fs::read_dir(&tmp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().to_string_lossy().ends_with(".bin.zst"))
        .collect();

    assert!(
        zst_files.len() > 1,
        "expected multiple files from rotation, got {}",
        zst_files.len()
    );

    let mut archive_names: Vec<_> = zst_files
        .iter()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    archive_names.sort();

    // decompress and count total events
    let mut total_events = 0;
    for entry in &zst_files {
        let archive = ArchiveReader::open(&entry.path()).unwrap();
        println!("header: {}", archive.header);
        total_events += archive.count();
    }

    println!("\n========== ROTATION TEST ==========");
    println!("files created: {}", zst_files.len());
    println!("total events:  {}", total_events);
    println!("===================================\n");

    assert_eq!(total_events, 8);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Archiver writes events, replayer reads them back, verify they match.
#[tokio::test]
async fn test_replayer_roundtrip() {
    setup();

    let tmp_dir = std::env::temp_dir().join("archiver_test_replayer_roundtrip");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let mut archiver_handle = tokio::spawn(async move {
        let args = make_test_args(nats_server.port, &dir);
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin.zst")
        .into_iter()
        .next()
        .expect("expected a .<timestamp>.bin.zst file");

    let archive = ArchiveReader::open(&archive_path).unwrap();

    for ((sent, _label), decoded) in all_events.iter().zip(archive) {
        assert_eq!(
            sent.peer_observer_event,
            decoded.unwrap().peer_observer_event
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn test_replayer_roundtrip_uncompressed() {
    setup();

    let tmp_dir = std::env::temp_dir().join(format!(
        "archiver_test_replayer_roundtrip_uncompressed_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let mut archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.compression_level = 0;
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin")
        .into_iter()
        .next()
        .expect("expected a .0.bin file");

    let archive = ArchiveReader::open(&archive_path).unwrap();
    for ((sent, _label), decoded) in all_events.iter().zip(archive) {
        assert_eq!(
            sent.peer_observer_event,
            decoded.unwrap().peer_observer_event
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn test_no_compression() {
    setup();

    let tmp_dir = std::env::temp_dir().join("archiver_test_no_compression");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let mut archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.compression_level = 0;
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    // should be .bin, not .bin.zst
    let bin_files = find_files(&tmp_dir, ".bin");
    assert!(!bin_files.is_empty(), ".0.bin file should exist");
    let zst_files = find_files(&tmp_dir, ".bin.zst");
    assert!(zst_files.is_empty(), ".0.bin.zst file should not exist");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// The archiver must shut down even when the NATS server is gone. Draining an
/// unreachable subscription never completes: the client reconnects instead of
/// processing the unsubscribe, so the subscription is never closed.
#[tokio::test]
async fn test_shutdown_with_unreachable_nats() {
    setup();

    let tmp_dir = std::env::temp_dir().join("archiver_test_shutdown_unreachable");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    // Keep ownership of the server here so it can be killed mid-test.
    let nats_port = nats_server.port;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.clone();
    let mut archiver_handle = tokio::spawn(async move {
        let args = make_test_args(nats_port, &dir);
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    // Kill the NATS server while the archiver is connected to it.
    drop(nats_server);
    sleep(Duration::from_millis(200)).await;

    let start = Instant::now();
    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(20), archiver_handle)
        .await
        .expect("archiver should shut down without a reachable NATS server")
        .unwrap();
    assert!(
        start.elapsed() >= DRAIN_TIMEOUT,
        "archiver should exit through the drain timeout path"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Publishes a tx and a block message and returns the archived events.
async fn archive_tx_and_block(low_data: bool, tmp_dir: &std::path::Path) -> Vec<Event> {
    setup();

    let _ = std::fs::remove_dir_all(tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();

    let dir = tmp_dir.to_path_buf();
    let mut archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.low_data = low_data;
        args.messages = low_data;
        run(args, shutdown_rx, Some(ready_tx)).await.unwrap();
    });

    wait_for_archiver_ready(ready_rx, &mut archiver_handle).await;

    let transaction = bitcoin_primitives::Transaction {
        txid: vec![0x11; 32],
        wtxid: vec![0x22; 32],
        raw: Some(vec![0xff; 500]),
    };
    let header = bitcoin_primitives::BlockHeader {
        version: 1,
        prev_blockhash: vec![0u8; 32],
        merkle_root: vec![0u8; 32],
        time: 1234,
        bits: 5678,
        nonce: 42,
        hash: vec![0x33; 32],
    };
    let events = [
        Msg::Tx(message::Tx {
            tx: transaction.clone(),
        }),
        Msg::Block(message::Block {
            header,
            transactions: vec![transaction],
        }),
    ]
    .map(|msg| {
        Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
                meta: Metadata {
                    peer_id: 0,
                    addr: "127.0.0.1:8333".to_string(),
                    conn_type: 1,
                    command: String::new(),
                    inbound: true,
                    size: 0,
                },
                msg: Some(msg),
            })),
        }))
        .unwrap()
    });

    for event in &events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    nats_publisher.sync().await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(tmp_dir, ".bin.zst")
        .into_iter()
        .next()
        .expect("expected a .<timestamp>.bin.zst file");
    let archive = ArchiveReader::open(&archive_path).unwrap();
    assert_eq!(
        archive.header.low_data,
        Some(low_data),
        "the archive header should record the low-data mode"
    );

    archive.map(|event| event.unwrap()).collect()
}

#[tokio::test]
async fn test_low_data_strips_transaction_raw_and_block_transactions() {
    let tmp_dir = std::env::temp_dir().join("archiver_test_low_data");
    let archived = archive_tx_and_block(true, &tmp_dir).await;

    let [tx_event, block_event] = &archived[..] else {
        panic!("expected a tx and a block event, got {}", archived.len());
    };

    let Msg::Tx(tx) = msg_of(tx_event) else {
        panic!("expected a tx message");
    };
    assert_eq!(tx.tx.raw, None, "raw transaction data should be stripped");
    assert_eq!(tx.tx.txid, vec![0x11; 32], "the txid should be kept");
    assert_eq!(tx.tx.wtxid, vec![0x22; 32], "the wtxid should be kept");

    let Msg::Block(block) = msg_of(block_event) else {
        panic!("expected a block message");
    };
    assert_eq!(
        block.header.hash,
        vec![0x33; 32],
        "the block header should be kept"
    );
    assert!(
        block.transactions.is_empty(),
        "block transactions should be removed in low-data mode"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn test_without_low_data_transaction_and_block_data_are_archived() {
    let tmp_dir = std::env::temp_dir().join("archiver_test_full_data");
    let archived = archive_tx_and_block(false, &tmp_dir).await;

    let [tx_event, block_event] = &archived[..] else {
        panic!("expected a tx and a block event, got {}", archived.len());
    };

    let Msg::Tx(tx) = msg_of(tx_event) else {
        panic!("expected a tx message");
    };
    assert_eq!(tx.tx.raw, Some(vec![0xff; 500]));

    let Msg::Block(block) = msg_of(block_event) else {
        panic!("expected a block message");
    };
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.transactions[0].raw, Some(vec![0xff; 500]));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Returns the P2P message of an event, panicking if there is none.
fn msg_of(event: &Event) -> &Msg {
    match event.peer_observer_event.as_ref().unwrap() {
        PeerObserverEvent::EbpfExtractor(ebpf) => match ebpf.ebpf_event.as_ref().unwrap() {
            ebpf::EbpfEvent::Message(message_event) => message_event.msg.as_ref().unwrap(),
            _ => panic!("expected a P2P message event"),
        },
        _ => panic!("expected an ebpf event"),
    }
}
