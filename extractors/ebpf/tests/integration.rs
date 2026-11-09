#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use shared::{
    async_nats,
    bitcoin::{self, Amount},
    bitcoind,
    futures::StreamExt,
    log::{self, debug},
    nats_util::NatsArgs,
    prost::Message,
    protobuf::{
        ebpf_extractor::{connection, ebpf::EbpfEvent, mempool, message, validation},
        event::{event::PeerObserverEvent, Event},
    },
    simple_logger::SimpleLogger,
    testing::{nats_server::NatsServerForTesting, REGTEST_ADDRESS},
    tokio::{
        self,
        sync::{oneshot, watch},
        time::{timeout, Duration},
    },
};

use ebpf_extractor::Args;

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Once;
use std::thread;

static INIT: Once = Once::new();

/// Coins from a mined block can only be spent 100 blocks later. Mining a few
/// more gives the tests that send transactions something to spend.
const BLOCKS_TO_MINE: usize = 110;

/// How long we wait for the extractor to hook into the node.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long we wait for the event a test is after.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Debug)
            .init()
            .unwrap();
    });
}

/// The extractor loads its tracing code into the Linux kernel, which needs
/// privileges a normal user account does not have.
fn running_as_root() -> bool {
    // The /proc directory of a process belongs to the user it runs as.
    match std::fs::metadata("/proc/self") {
        Ok(metadata) => metadata.uid() == 0,
        Err(e) => {
            log::warn!("could not read /proc/self to see which user we are: {}", e);
            false
        }
    }
}

#[derive(Default)]
struct EnabledTracepointsInTest {
    p2p_messages: bool,
    connections: bool,
    mempool: bool,
    validation: bool,
}

fn make_test_args(
    nats_port: u16,
    bitcoind_path: String,
    pid_file: PathBuf,
    tracepoints: EnabledTracepointsInTest,
) -> Args {
    Args {
        nats: NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        bitcoind_path,
        bitcoind_pid: None,
        bitcoind_pid_file: Some(pid_file.display().to_string()),
        no_p2pmsg_tracepoints: !tracepoints.p2p_messages,
        no_connection_tracepoints: !tracepoints.connections,
        no_mempool_tracepoints: !tracepoints.mempool,
        no_validation_tracepoints: !tracepoints.validation,
        log_level: log::Level::Debug,
        libbpf_debug: false,
        // The extractor would stop after a few minutes without events. The
        // tests are shorter than that, but we don't want it to stop on us.
        no_idle_exit: true,
    }
}

/// The bitcoind binary the tests run. The extractor hooks into the same file,
/// otherwise it would look for the tracepoints in the wrong place.
fn bitcoind_path() -> String {
    bitcoind::exe_path().expect("could not find a bitcoind binary to test with")
}

fn start_node() -> bitcoind::BitcoinD {
    let mut conf = bitcoind::Conf::default();
    conf.args = vec![
        "-regtest",
        // The tests connect the two nodes themselves, so the node should not
        // go looking for peers on its own.
        "-connect=0",
        "-listen=1",
        "-fallbackfee=0.0001",
    ];
    conf.p2p = bitcoind::P2P::Yes;
    conf.view_stdout = false;
    bitcoind::BitcoinD::with_conf(bitcoind_path(), &conf).expect("could not start a bitcoind")
}

/// Starts a NATS server, a Bitcoin Core node to hook into, a second node to
/// connect to, and the extractor. Waits until the extractor says it is hooked
/// in, then runs `activity` and waits for `expected` to accept one of the
/// published events.
async fn check(
    tracepoints: EnabledTracepointsInTest,
    activity: impl FnOnce(&bitcoind::BitcoinD, &bitcoind::BitcoinD),
    mut expected: impl FnMut(EbpfEvent) -> bool,
) {
    // The tests are marked as ignored, so we only get here when someone asked
    // for them. Saying why they cannot run beats loading nothing and passing.
    assert!(
        running_as_root(),
        "these tests load tracing code into the kernel and have to run as root"
    );

    setup();

    let nats_server = NatsServerForTesting::new(&[]).await;
    let node = start_node();
    let peer = start_node();

    // Mine to our own wallet, so that the tests sending transactions have coins.
    let mining_address = node
        .client
        .get_new_address(None, None)
        .unwrap()
        .address()
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    node.client
        .generate_to_address(BLOCKS_TO_MINE, &mining_address)
        .unwrap();

    // bitcoind writes this file on startup. The extractor reads the process id
    // it needs to hook into from it.
    let pid_file = node.workdir().join("regtest").join("bitcoind.pid");
    assert!(pid_file.exists(), "bitcoind did not write {:?}", pid_file);

    // Subscribe before the extractor starts, so that we can't miss an event.
    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
        .await
        .unwrap();
    let mut subscription = nc.subscribe("*").await.unwrap();

    let args = make_test_args(nats_server.port, bitcoind_path(), pid_file, tracepoints);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    // The extractor holds libbpf types that can't be moved between threads, so
    // it can't run as a task next to this test. It also blocks while reading
    // its buffers, so it gets a runtime with more than one thread and can keep
    // publishing while it does.
    let extractor = thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("could not build a runtime for the ebpf-extractor")
            .block_on(ebpf_extractor::run(args, shutdown_rx, Some(ready_tx)))
    });

    // Wait until the extractor is hooked into the node. Anything the node does
    // before that it would not see.
    if !matches!(timeout(STARTUP_TIMEOUT, ready_rx).await, Ok(Ok(()))) {
        if extractor.is_finished() {
            let result = extractor.join().expect("the ebpf-extractor panicked");
            panic!("the ebpf-extractor stopped while starting up: {:?}", result);
        }
        panic!(
            "the ebpf-extractor was not ready within {:?}",
            STARTUP_TIMEOUT
        );
    }

    activity(&node, &peer);

    let found = timeout(TEST_TIMEOUT, async {
        while let Some(nats_message) = subscription.next().await {
            let event = Event::decode(nats_message.payload).expect("could not decode an event");
            if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = event.peer_observer_event {
                if let Some(ebpf_event) = ebpf.ebpf_event {
                    debug!("received an event: {}", ebpf_event);
                    if expected(ebpf_event) {
                        return;
                    }
                }
            }
        }
        panic!("the NATS subscription ended");
    })
    .await;

    shutdown_tx.send(true).unwrap();
    extractor
        .join()
        .expect("the ebpf-extractor panicked")
        .expect("the ebpf-extractor failed");

    assert!(
        found.is_ok(),
        "no event we were waiting for within {:?}",
        TEST_TIMEOUT
    );
}

/// Connects the node we hook into to the second node.
fn connect_nodes(node: &bitcoind::BitcoinD, peer: &bitcoind::BitcoinD) {
    let address = peer
        .params
        .p2p_socket
        .expect("the second node should listen for connections");
    node.client
        .add_connection(&address.to_string(), "outbound-full-relay", true)
        .expect("could not connect the two nodes");
}

#[tokio::test]
#[ignore = "needs root: loads tracing code into the kernel"]
async fn test_integration_ebpfextractor_block_connected() {
    println!("test that we receive a block connected event when the node mines a block");

    check(
        EnabledTracepointsInTest {
            validation: true,
            ..Default::default()
        },
        |node, _peer| {
            node.client
                .generate_to_address(1, &REGTEST_ADDRESS)
                .unwrap();
        },
        |event| match event {
            EbpfEvent::Validation(validation) => match validation.event {
                Some(validation::validation_event::Event::BlockConnected(block)) => {
                    assert_eq!(block.hash.len(), 32);
                    assert_eq!(block.height, BLOCKS_TO_MINE as i32 + 1);
                    // The block we mine holds nothing but its coinbase.
                    assert_eq!(block.transactions, 1);
                    true
                }
                None => false,
            },
            _ => false,
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "needs root: loads tracing code into the kernel"]
async fn test_integration_ebpfextractor_mempool_added() {
    println!("test that we receive a mempool event when the node accepts a transaction");

    check(
        EnabledTracepointsInTest {
            mempool: true,
            ..Default::default()
        },
        |node, _peer| {
            node.client
                .send_to_address(&REGTEST_ADDRESS, Amount::from_sat(100_000))
                .unwrap();
        },
        |event| match event {
            EbpfEvent::Mempool(mempool) => match mempool.event {
                Some(mempool::mempool_event::Event::Added(added)) => {
                    assert_eq!(added.txid.len(), 32);
                    assert!(added.vsize > 0);
                    assert!(added.fee > 0);
                    true
                }
                _ => false,
            },
            _ => false,
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "needs root: loads tracing code into the kernel"]
async fn test_integration_ebpfextractor_outbound_connection() {
    println!("test that we receive a connection event when the node connects to a peer");

    check(
        EnabledTracepointsInTest {
            connections: true,
            ..Default::default()
        },
        connect_nodes,
        |event| match event {
            EbpfEvent::Connection(conn) => match conn.event {
                Some(connection::connection_event::Event::Outbound(outbound)) => {
                    assert!(!outbound.conn.addr.is_empty());
                    true
                }
                _ => false,
            },
            _ => false,
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "needs root: loads tracing code into the kernel"]
async fn test_integration_ebpfextractor_p2p_message() {
    println!("test that we receive P2P messages the node sends and receives");

    check(
        EnabledTracepointsInTest {
            p2p_messages: true,
            ..Default::default()
        },
        connect_nodes,
        |event| match event {
            EbpfEvent::Message(msg) => {
                // Both sides start with a version message, so we are sure to
                // see one. Other messages carry less we can check.
                if msg.meta.command != "version" {
                    return false;
                }
                assert!(msg.meta.size > 0);
                assert!(!msg.meta.addr.is_empty());
                assert!(matches!(
                    msg.msg,
                    Some(message::message_event::Msg::Version(_))
                ));
                true
            }
            _ => false,
        },
    )
    .await;
}
