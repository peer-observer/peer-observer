#![cfg(feature = "nats_integration_tests")]

use archive::archiver::{run, Args};
use archive::replayer::read_archive;

use shared::{
    log,
    nats_subjects::Subject,
    nats_util,
    prost::Message,
    protobuf::{
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
    tokio::{self, sync::watch, time::sleep},
};
use std::{sync::Once, time::Duration};

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

async fn run_filter_test(flag: &str, expected_count: usize) {
    setup();

    let tmp_dir = std::env::temp_dir().join(format!("archiver_test_{}", flag));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let dir = tmp_dir.clone();
    let flag_owned = flag.to_string();
    let archiver_handle = tokio::spawn(async move {
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
        run(args, shutdown_rx).await.unwrap();
    });

    sleep(Duration::from_secs(1)).await;

    let all_events = make_all_event_types();
    for (event, _label) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(500)).await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin.zst")
        .into_iter()
        .next()
        .expect("expected a .<timestamp>.bin.zst file");

    let archive = read_archive(&archive_path).unwrap();

    assert_eq!(archive.events.len(), expected_count);

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

    let dir = tmp_dir.clone();
    let archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.max_file_size = 1; // force rotation on every event
        args.compression_level = 1;
        run(args, shutdown_rx).await.unwrap();
    });

    sleep(Duration::from_secs(1)).await;

    let all_events = make_all_event_types();
    for (event, _label) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(500)).await;
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
        let archive = read_archive(&entry.path()).unwrap();
        total_events += archive.events.len();
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

    let dir = tmp_dir.clone();
    let archiver_handle = tokio::spawn(async move {
        let args = make_test_args(nats_server.port, &dir);
        run(args, shutdown_rx).await.unwrap();
    });

    sleep(Duration::from_secs(1)).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(500)).await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin.zst")
        .into_iter()
        .next()
        .expect("expected a .<timestamp>.bin.zst file");
    let archive = read_archive(&archive_path).unwrap();

    assert_eq!(archive.events.len(), all_events.len());

    for ((sent, _label), decoded) in all_events.iter().zip(archive.events.iter()) {
        assert_eq!(sent.peer_observer_event, decoded.peer_observer_event);
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

    let dir = tmp_dir.clone();
    let archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.compression_level = 0;
        run(args, shutdown_rx).await.unwrap();
    });

    sleep(Duration::from_secs(1)).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(500)).await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    let archive_path = find_files(&tmp_dir, ".bin")
        .into_iter()
        .next()
        .expect("expected a .0.bin file");
    let archive = read_archive(&archive_path).unwrap();

    assert_eq!(archive.events.len(), all_events.len());

    for ((sent, _label), decoded) in all_events.iter().zip(archive.events.iter()) {
        assert_eq!(sent.peer_observer_event, decoded.peer_observer_event);
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

    let dir = tmp_dir.clone();
    let archiver_handle = tokio::spawn(async move {
        let mut args = make_test_args(nats_server.port, &dir);
        args.compression_level = 0;
        run(args, shutdown_rx).await.unwrap();
    });

    sleep(Duration::from_secs(1)).await;

    let all_events = make_all_event_types();
    for (event, _) in &all_events {
        nats_publisher
            .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
            .await;
    }

    sleep(Duration::from_millis(500)).await;
    shutdown_tx.send(true).unwrap();
    archiver_handle.await.unwrap();

    // should be .bin, not .bin.zst
    let bin_files = find_files(&tmp_dir, ".bin");
    assert!(!bin_files.is_empty(), ".0.bin file should exist");
    let zst_files = find_files(&tmp_dir, ".bin.zst");
    assert!(zst_files.is_empty(), ".0.bin.zst file should not exist");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
