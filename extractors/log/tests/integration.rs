#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use log_extractor::Args;
use shared::{
    async_nats,
    bitcoin::{self, Block, consensus::Decodable, hashes::Hash, hex::FromHex},
    corepc_node,
    futures::StreamExt,
    log::{Level, LevelFilter, info},
    nats_util::NatsArgs,
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        log_extractor::{LogDebugCategory, log},
    },
    simple_logger::SimpleLogger,
    testing::nats_server::NatsServerForTesting,
    tokio::{
        self, select,
        sync::watch,
        time::{Duration, sleep},
    },
};
use std::io::Write;
use std::str::FromStr;
use std::sync::Once;

static INIT: Once = Once::new();

// 10 second check() timeout.
const TEST_TIMEOUT_SECONDS: u64 = 10;

fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

/// Appends a marker line to `debug.log` with a valid RFC 3339 timestamp so the
/// log parser treats it as an `UnknownLogMessage`.
fn write_marker(log_path: &str, marker: &str) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
        .expect("failed to open debug.log for appending");
    writeln!(file, "2026-01-01T00:00:00Z {marker}").expect("failed to write marker");
}

/// Waits until `marker` arrives via NATS as an `UnknownLogMessage`, proving the
/// full debug.log -> tail -> pipe -> extractor -> NATS pipeline is live.
/// Returns any `PeerObserverEvent`s consumed before the marker so callers can
/// replay them through their assertion logic (prevents event starvation).
/// Panics on timeout.
async fn wait_for_marker(
    sub: &mut shared::async_nats::Subscriber,
    marker: &str,
    timeout: Duration,
) -> Vec<PeerObserverEvent> {
    let mut buffered = Vec::new();
    let mut marker_seen = false;
    select! {
        _ = sleep(timeout) => {
            panic!("timed out waiting for pipeline-ready marker '{marker}'");
        }
        _ = async {
            while let Some(msg) = sub.next().await {
                if let Ok(event) = Event::decode(msg.payload) {
                    if let Some(PeerObserverEvent::LogExtractor(ref r)) = event.peer_observer_event
                        && let Some(log::LogEvent::UnknownLogMessage(ref u)) = r.log_event
                        && u.raw_message.contains(marker)
                    {
                        info!("received pipeline-ready marker: {marker}");
                        marker_seen = true;
                        return;
                    }
                    if let Some(pe) = event.peer_observer_event {
                        buffered.push(pe);
                    }
                }
            }
        } => {}
    }
    assert!(
        marker_seen,
        "NATS subscription stream closed before pipeline-ready marker '{marker}' arrived"
    );
    buffered
}

/// Bridges Bitcoin Core's `debug.log` into a named pipe for the log extractor.
///
/// The log extractor reads from a pipe (not a regular file), so we create one
/// with `mkfifo` and spawn a background `tail -f` process that continuously
/// streams new log lines from `log_path` into `pipe_path`.
fn spawn_pipe(log_path: String, pipe_path: String) {
    // Create pipe
    std::process::Command::new("mkfifo")
        .arg(&pipe_path)
        .status()
        .expect("Failed to create named pipe");
    info!("Created named pipe at {}", &pipe_path);

    // Start tail -f from debug.log to the pipe
    info!("Running: bash -c 'tail -f {} > {}'", log_path, pipe_path);
    tokio::process::Command::new("bash")
        .arg("-c")
        .arg(format!("tail -f {} > {}", log_path, pipe_path))
        .spawn()
        .expect("Failed to spawn tail");
}

fn make_test_args(nats_port: u16, bitcoind_pipe: String) -> Args {
    Args::new(
        NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        bitcoind_pipe,
        Level::Trace,
    )
}

/// Starts a regtest `bitcoind` node with the given configuration.
///
/// The binary is resolved from the `BITCOIND_EXE` environment variable
/// (via `corepc_node::exe_path`); if unset, a pre-built binary is
/// downloaded automatically.
fn setup_node(conf: corepc_node::Conf) -> corepc_node::Node {
    info!("env BITCOIND_EXE={:?}", std::env::var("BITCOIND_EXE"));
    info!("exe_path={:?}", corepc_node::exe_path());

    if let Ok(exe_path) = corepc_node::exe_path() {
        info!("Using bitcoind at '{}'", exe_path);
        return corepc_node::Node::with_conf(exe_path, &conf).unwrap();
    }

    info!("Trying to download a bitcoind..");
    corepc_node::Node::from_downloaded_with_conf(&conf).unwrap()
}

/// Creates a two-node regtest topology:
/// - node1 listens for inbound P2P connections
/// - node2 connects to node1.
///
/// `node1_args` are appended as extra `bitcoind` CLI flags (e.g. `-debug=validation`) so tests
/// can enable the specific logging needed to trigger the events they want to observe.
fn setup_two_connected_nodes(node1_args: Vec<&str>) -> (corepc_node::Node, corepc_node::Node) {
    // node1 listens for p2p connections
    let mut node1_conf = corepc_node::Conf::default();
    node1_conf.p2p = corepc_node::P2P::Yes;
    for arg in node1_args {
        info!("Running node1 with arg: {}", arg);
        node1_conf.args.push(arg);
    }
    let node1 = setup_node(node1_conf);

    // node2 connects to node1
    let mut node2_conf = corepc_node::Conf::default();
    node2_conf.p2p = node1.p2p_connect(true).unwrap();
    let node2 = setup_node(node2_conf);

    (node1, node2)
}

/// Integration test harness that verifies the log extractor produces expected
/// NATS events in response to Bitcoin Core activity.
///
/// 1. Initializes logging and spins up two connected regtest nodes (node1
///    accepts inbound P2P; node2 connects to it). `args` are passed as extra
///    bitcoind CLI flags to node1 (e.g. `-debug=validation`).
/// 2. Starts a throwaway NATS server and subscribes *before* launching the
///    extractor, so startup events are not lost.
/// 3. Launches the log extractor, which reads node1's `debug.log` via a named
///    pipe (`mkfifo` + `tail -f`) and publishes protobuf-encoded events to
///    NATS.
/// 4. Performs an end-to-end pipeline handshake: writes a unique marker line
///    into `debug.log` and waits for it to arrive via NATS, buffering any
///    events consumed before the marker. This proves the full
///    `debug.log -> tail -> pipe -> extractor -> NATS` path is live.
/// 5. Calls `test_setup` against node1's RPC client so the test can trigger
///    the specific node behaviour it wants to observe (mine a block, submit a
///    transaction, etc.).
/// 6. Replays buffered pre-marker events through `check_event`, then polls
///    live NATS messages. The loop breaks as soon as `check_event` returns
///    `true`.
/// 7. Panics if the expected event is not seen within `TEST_TIMEOUT_SECONDS`.
/// 8. Sends a shutdown signal to the log extractor task and awaits its clean
///    exit before returning.
async fn check(
    args: Vec<&str>,
    test_setup: fn(&corepc_node::Client),
    check_event: fn(PeerObserverEvent) -> bool,
) {
    setup();
    let (node1, _node2) = setup_two_connected_nodes(args);
    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_port = nats_server.port;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Subscribe BEFORE spawning the extractor so that startup events
    // published between extractor start and subscription are not lost.
    // Without this, tests with no-op test_setup() starve because the
    // only events they could ever match were already published.
    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_port))
        .await
        .unwrap();
    let mut sub = nc.subscribe("*").await.unwrap();

    let node1_workdir = node1.workdir().to_str().unwrap().to_string();
    let log_path = format!("{}/regtest/debug.log", node1_workdir);
    let log_path_main = log_path.clone();
    let log_extractor_handle = tokio::spawn(async move {
        let pipe_path = format!("{}/bitcoind_pipe", node1_workdir);
        spawn_pipe(log_path, pipe_path.clone());

        let args = make_test_args(nats_port, pipe_path.to_string());

        log_extractor::run(args, shutdown_rx.clone())
            .await
            .expect("log extractor failed");
    });

    // End-to-end pipeline handshake: write a unique marker into debug.log
    // and wait for it to arrive via NATS, proving the full
    // debug.log -> tail -> pipe -> extractor -> NATS path is live.
    // Events consumed before the marker are buffered for replay.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let marker = format!("PIPELINE_READY:{nanos}");
    write_marker(&log_path_main, &marker);
    let buffered = wait_for_marker(&mut sub, &marker, Duration::from_secs(10)).await;

    test_setup(&node1.client);

    sleep(Duration::from_secs(1)).await;

    select! {
        _ = sleep(Duration::from_secs(TEST_TIMEOUT_SECONDS)) => {
            panic!("timed out waiting for check() to complete");
        }
        _ = async {
            // Replay events consumed during the marker handshake so tests
            // that rely on early/startup events are not starved.
            for event in buffered {
                if check_event(event) {
                    return;
                }
            }
            while let Some(msg) = sub.next().await {
                let unwrapped = Event::decode(msg.payload).unwrap();
                if let Some(event) = unwrapped.peer_observer_event
                    && check_event(event)
                {
                    break;
                }
            }
        } => {},
    }

    shutdown_tx.send(true).unwrap();
    log_extractor_handle.await.unwrap();
}

pub fn update_merkle_root(block: &mut Block) {
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

pub fn mine_block(block: &mut Block) {
    let target = block.header.target();
    while block.header.validate_pow(target).is_err() {
        block.header.nonce += 1;
    }
}

#[tokio::test]
async fn test_integration_logextractor_log_events() {
    println!("test that we receive log events");

    check(
        vec![],
        |_node1| (),
        |event| match event {
            PeerObserverEvent::LogExtractor(r) => r.log_event.is_some(),
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_unknown_log_events() {
    println!("test that we receive unknown log events");

    check(
        vec![],
        |_node1| (),
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::UnknownLogMessage(unknown_log_message) = e
                    {
                        assert!(!unknown_log_message.raw_message.is_empty());
                        info!("UnknownLogMessage {:?}", unknown_log_message);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_block_connected() {
    println!("test that we receive block connected log events");

    check(
        vec!["-debug=validation"],
        |node1| {
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();
            node1.generate_to_address(1, &address).unwrap();
        },
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::BlockConnectedLog(block_connected) = e
                    {
                        assert!(block_connected.block_height > 0);
                        info!("BlockConnectedLog event {}", block_connected);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_logtimemicros() {
    println!("test that we can parse -logtimemicros timestamps");

    check(
        vec!["-logtimemicros=1"],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    // When using -logtimemicros=1, the timestamp % 1000 should
                    // (most of the time) be != 0 (or >0). 1 in 1000 cases, it will
                    // be 0, but we test multiple messages.
                    r.log_timestamp % 1000 > 0
                }
                _ => panic!("unexpected event {:?}", event),
            }
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_extralogging() {
    println!("test that we can parse -logthreadnames=1 and -logsourcelocations=1 lines too");

    check(
        vec![
            "-debug=validation",
            "-logthreadnames=1",
            "-logsourcelocations=1",
            "-logips=1",
            "-logtimemicros=1",
        ],
        |node1| {
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();
            node1.generate_to_address(1, &address).unwrap();
        },
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::BlockConnectedLog(block_connected) = e
                    {
                        assert!(block_connected.block_height > 0);
                        info!("BlockConnectedLog event {}", block_connected);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_block_checked() {
    println!("test that we receive block checked log events");

    check(
        vec!["-debug=validation"],
        |node1| {
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();
            node1.generate_to_address(1, &address).unwrap();
        },
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(log::LogEvent::BlockCheckedLog(block_checked)) = r.log_event
                        && block_checked.state == "Valid"
                    {
                        assert!(!block_checked.block_hash.is_empty());
                        info!("BlockCheckedLog event {}", block_checked);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_mutated_block_bad_witness_nonce_size() {
    println!("test that we receive block mutated log events (bad-witness-nonce-size)");

    check(
        vec!["-debug=validation"],
        |node1| {
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();

            let block = node1
                .generate_block(&address.to_string(), &[], false)
                .unwrap();
            let block_hex = block.hex.unwrap();
            let block_bytes: Vec<u8> = FromHex::from_hex(&block_hex).unwrap();
            let mut block = Block::consensus_decode(&mut block_bytes.as_slice()).unwrap();

            let coinbase = block.txdata.first_mut().unwrap();
            coinbase.input[0].witness.push([0]);

            update_merkle_root(&mut block);
            mine_block(&mut block);

            assert!(
                node1.submit_block(&block).is_err(),
                "expected block submission to fail"
            );
        },
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::BlockCheckedLog(block_checked) = e
                        && block_checked.state == "bad-witness-nonce-size"
                    {
                        assert_eq!(
                            block_checked.debug_message,
                            "CheckWitnessMalleation : invalid witness reserved value size"
                        );
                        info!("BlockCheckedLog event {}", block_checked);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_mutated_block_bad_txnmrklroot() {
    println!("test that we receive block mutated log events (bad-txnmrklroot)");

    check(
        vec!["-debug=validation"],
        |node1| {
            let address: bitcoin::address::Address =
                bitcoin::address::Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap();

            let block = node1
                .generate_block(&address.to_string(), &[], false)
                .unwrap();
            let block_hex = block.hex.unwrap();
            let block_bytes: Vec<u8> = FromHex::from_hex(&block_hex).unwrap();
            let mut block = Block::consensus_decode(&mut block_bytes.as_slice()).unwrap();

            let merkle_root = block.header.merkle_root;
            let mut bytes = *merkle_root.as_raw_hash().as_byte_array();
            bytes[0] ^= 0x55;
            block.header.merkle_root = Hash::from_byte_array(bytes);

            mine_block(&mut block);

            assert!(
                node1.submit_block(&block).is_err(),
                "expected block submission to fail"
            );
        },
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(l) => {
                    if let Some(ref e) = l.log_event
                        && let log::LogEvent::BlockCheckedLog(block_checked) = e
                        && block_checked.state == "bad-txnmrklroot"
                    {
                        assert_eq!(block_checked.debug_message, "hashMerkleRoot mismatch");
                        info!("BlockCheckedLog event {}", block_checked);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_unknown_with_threadname() {
    println!("test that we receive unknown log events with threadname");

    check(
        vec!["-logthreadnames=1"],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::UnknownLogMessage(unknown_log_message) = e
                        && !r.threadname.is_empty()
                        && r.category == LogDebugCategory::Unknown as i32
                    {
                        assert!(!unknown_log_message.raw_message.is_empty());
                        info!("UnknownLogMessage with threadname: {}", r.threadname);
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_unknown_with_category() {
    println!("test that we receive unknown log events with category");

    check(
        vec!["-debug=net"],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::UnknownLogMessage(unknown_log_message) = e
                        && r.category == LogDebugCategory::Net as i32
                    {
                        assert!(!unknown_log_message.raw_message.is_empty());
                        info!("UnknownLogMessage with category Net");
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_unknown_with_threadname_and_category() {
    println!("test that we receive unknown log events with threadname and category");

    check(
        vec!["-logthreadnames=1", "-debug=net"],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::UnknownLogMessage(unknown_log_message) = e
                        && r.category == LogDebugCategory::Net as i32
                    {
                        assert!(!unknown_log_message.raw_message.is_empty());
                        assert!(!r.threadname.is_empty(), "threadname should not be empty");
                        info!(
                            "UnknownLogMessage with threadname {} and category Net",
                            r.threadname
                        );
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_unknown_with_all_metadata() {
    println!("test that we receive unknown log events with all metadata");

    check(
        vec!["-logthreadnames=1", "-logsourcelocations=1", "-debug=net"],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(r) => {
                    if let Some(ref e) = r.log_event
                        && let log::LogEvent::UnknownLogMessage(unknown_log_message) = e
                        && r.category == LogDebugCategory::Net as i32
                    {
                        assert!(!unknown_log_message.raw_message.is_empty());
                        assert!(!r.threadname.is_empty(), "threadname should not be empty");
                        info!(
                            "UnknownLogMessage with threadname {} and category Net",
                            r.threadname
                        );
                        return true;
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
#[should_panic(expected = "timed out waiting for check() to complete")]
async fn test_integration_logextractor_testsshouldtimeout() {
    println!("test that we timeout long running tests");

    check(
        vec![],
        |_node1| {},
        |event| {
            match event {
                PeerObserverEvent::LogExtractor(_) => {
                    // do nothing
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_logextractor_log_bytes() {
    println!("test that we can parse log line bytes");

    check(
        vec!["-debug=net"],
        |_node1| {},
        |event| match event {
            PeerObserverEvent::LogExtractor(r) => {
                if let Some(log::LogEvent::UnknownLogMessage(_)) = r.log_event
                    && r.category == LogDebugCategory::Net as i32
                {
                    assert!(r.log_line_bytes > 0, "log_line_bytes should be > 0");
                    info!(
                        "Received log event with log_line_bytes={}",
                        r.log_line_bytes
                    );
                    return true;
                }
                false
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}
