#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use ipc_extractor::{self, Args};
use shared::{
    async_nats,
    bitcoin::{self, hashes::Hash},
    bitcoind,
    futures::StreamExt,
    log::{self, info},
    nats_util::NatsArgs,
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        ipc_extractor::ipc::IpcEvent::BlockTip,
    },
    simple_logger::SimpleLogger,
    testing::nats_server::NatsServerForTesting,
    tokio::{self, sync::watch, task::LocalSet, time::sleep},
};
use std::sync::Once;
use std::time::Duration;

pub const QUERY_INTERVAL_SECONDS: u64 = 1;

// 5 second check() timeout.
const TEST_TIMEOUT_SECONDS: u64 = 5;

pub fn make_test_args(nats_port: u16, ipc_socket_path: String) -> Args {
    Args {
        nats: NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        log_level: log::Level::Trace,
        ipc_socket_path,
        query_interval: QUERY_INTERVAL_SECONDS,
    }
}

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

fn bitcoin_node_exe_path() -> String {
    if let Ok(p) = std::env::var("BITCOIN_NODE_EXE") {
        return p;
    }
    let bitcoind_path =
        std::path::PathBuf::from(bitcoind::downloaded_exe_path().expect("downloaded_exe_path"));
    bitcoind_path
        .parent()
        .and_then(|p| p.parent())
        .expect("unexpected bitcoind path layout")
        .join("libexec")
        .join("bitcoin-node")
        .to_string_lossy()
        .into_owned()
}

fn setup_node(conf: bitcoind::Conf) -> bitcoind::BitcoinD {
    let exe_path = bitcoin_node_exe_path();
    info!("Using bitcoin-node at '{}'", exe_path);
    bitcoind::BitcoinD::with_conf(exe_path, &conf).unwrap()
}

fn configure_node() -> bitcoind::BitcoinD {
    let mut node_conf = bitcoind::Conf::default();
    node_conf.args = vec!["-regtest", "-ipcbind=unix"];
    // enabling this is useful for debugging, but enabling this by default will
    // be quite spammy.
    node_conf.view_stdout = false;
    // node_conf.wallet is `true` by default, but since `bitcoin-node` binary doesn't
    // have wallet capabilities we disable it
    node_conf.wallet = None;

    setup_node(node_conf)
}

async fn check(check_expected: fn(PeerObserverEvent) -> ()) {
    setup();
    let node = configure_node();
    let nats_server = NatsServerForTesting::new(&[]).await;

    let ipc_socket_path = node
        .workdir()
        .as_path()
        .join("regtest")
        .join("node.sock")
        .to_str()
        .unwrap()
        .into();

    let args = make_test_args(nats_server.port, ipc_socket_path);

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            let ipc_extractor_future = ipc_extractor::run(args, shutdown_rx.clone());
            tokio::pin!(ipc_extractor_future);

            let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
                .await
                .unwrap();
            let mut sub = nc.subscribe("*").await.unwrap();

            tokio::select! {
                _ = sleep(Duration::from_secs(TEST_TIMEOUT_SECONDS)) => {
                    panic!("timed out waiting for check() to complete");
                }
                msg = sub.next() => {
                    if let Some(msg) = msg {
                        let unwrapped = Event::decode(msg.payload).unwrap();
                        if let Some(event) = unwrapped.peer_observer_event {
                            check_expected(event);
                        }
                    } else {
                        panic!("subscription ended");
                    }
                }
                result = &mut ipc_extractor_future => {
                    panic!("ipc_extractor stopped unexpectedly: {:?}", result);
                }
            }

            shutdown_tx.send(true).unwrap();
            ipc_extractor_future.await.unwrap();
        })
        .await;
}

#[tokio::test]
async fn test_integration_ipc() {
    println!("test that we receive BlockTip IPC events");

    check(|event| match event {
        PeerObserverEvent::IpcExtractor(i) => {
            if let Some(ref e) = i.ipc_event {
                match e {
                    BlockTip(t) => {
                        assert_eq!(t.height, 0);
                        assert_eq!(t.hash.len(), 32);
                        assert_eq!(
                            bitcoin::BlockHash::from_slice(&t.hash).unwrap().to_string(),
                            // genesis blockhash in Regtest
                            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                        );
                    }
                }
            }
        }
        _ => panic!("unexpected event {:?}", event),
    })
    .await;
}

#[tokio::test]
async fn test_integration_ipc_node_shutdown() {
    println!("test that the ipc-extractor shuts down when the node is stopped");

    setup();
    let mut node = configure_node();
    let nats_server = NatsServerForTesting::new(&[]).await;

    let ipc_socket_path = node
        .workdir()
        .as_path()
        .join("regtest")
        .join("node.sock")
        .to_str()
        .unwrap()
        .into();

    let args = make_test_args(nats_server.port, ipc_socket_path);

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);

            let ipc_extractor_future = ipc_extractor::run(args, shutdown_rx.clone());
            tokio::pin!(ipc_extractor_future);

            let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
                .await
                .unwrap();
            let mut sub = nc.subscribe("*").await.unwrap();

            tokio::select! {
                _ = sleep(Duration::from_secs(TEST_TIMEOUT_SECONDS)) => {
                    panic!("timed out waiting for check() to complete");
                }
                msg = sub.next() => {
                    if let Some(msg) = msg {
                        let unwrapped = Event::decode(msg.payload).unwrap();
                        if unwrapped.peer_observer_event.is_some() {
                            // After we received the first message from the ipc-extractor,
                            // we shut down the node.
                            node.stop().unwrap();
                        }
                    } else {
                        panic!("subscription ended");
                    }
                }
                result = &mut ipc_extractor_future => {
                    panic!("ipc_extractor stopped unexpectedly: {:?}", result);
                }
            }

            assert_eq!(ipc_extractor_future.await.unwrap(), ());
        })
        .await;
}
