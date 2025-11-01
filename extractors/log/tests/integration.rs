#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

use log_extractor::Args;
use shared::{
    async_nats,
    bitcoin::{self, Block},
    corepc_node,
    futures::StreamExt,
    log,
    prost::Message,
    protobuf::{
        event_msg::{EventMsg, event_msg::Event},
        log_extractor::log_event,
    },
    simple_logger::SimpleLogger,
    testing::nats_server::NatsServerForTesting,
    tokio::{
        self,
        sync::watch,
        time::{Duration, sleep},
    },
};
use std::str::FromStr;
use std::sync::Once;

static INIT: Once = Once::new();

fn setup() -> () {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

fn spawn_pipe(log_path: String, pipe_path: String) -> () {
    // Create pipe
    std::process::Command::new("mkfifo")
        .arg(&pipe_path)
        .status()
        .expect("Failed to create named pipe");
    log::info!("Created named pipe at {}", &pipe_path);

    // Start tail -f from debug.log to the pipe
    log::info!("Running: bash -c 'tail -f {} > {}'", log_path, pipe_path);
    tokio::process::Command::new("bash")
        .arg("-c")
        .arg(format!("tail -f {} > {}", log_path, pipe_path))
        .spawn()
        .expect("Failed to spawn tail");
}

fn make_test_args(nats_port: u16, bitcoind_pipe: String) -> Args {
    Args::new(
        format!("127.0.0.1:{}", nats_port),
        bitcoind_pipe,
        log::Level::Trace,
    )
}

fn setup_node(conf: corepc_node::Conf) -> corepc_node::Node {
    log::info!("env BITCOIND_EXE={:?}", std::env::var("BITCOIND_EXE"));
    log::info!("exe_path={:?}", corepc_node::exe_path());

    if let Ok(exe_path) = corepc_node::exe_path() {
        log::info!("Using bitcoind at '{}'", exe_path);
        return corepc_node::Node::with_conf(exe_path, &conf).unwrap();
    }

    log::info!("Trying to download a bitcoind..");
    return corepc_node::Node::from_downloaded_with_conf(&conf).unwrap();
}

fn setup_two_connected_nodes(node1_args: Vec<&str>) -> (corepc_node::Node, corepc_node::Node) {
    // node1 listens for p2p connections
    let mut node1_conf = corepc_node::Conf::default();
    node1_conf.p2p = corepc_node::P2P::Yes;
    for arg in node1_args {
        log::info!("Running node1 with arg: {}", arg);
        node1_conf.args.push(arg);
    }
    let node1 = setup_node(node1_conf);

    // node2 connects to node1
    let mut node2_conf = corepc_node::Conf::default();
    node2_conf.p2p = node1.p2p_connect(true).unwrap();
    let node2 = setup_node(node2_conf);

    (node1, node2)
}

async fn check(
    args: Vec<&str>,
    test_setup: fn(&corepc_node::Client),
    check_event: fn(Event) -> bool,
) {
    setup();
    let (node1, _node2) = setup_two_connected_nodes(args);
    let nats_server = NatsServerForTesting::new().await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let node1_workdir = node1.workdir().to_str().unwrap().to_string();
    let log_extractor_handle = tokio::spawn(async move {
        let log_path = format!("{}/regtest/debug.log", node1_workdir);
        let pipe_path = format!("{}/bitcoind_pipe", node1_workdir);
        spawn_pipe(log_path, pipe_path.clone());

        let args = make_test_args(nats_server.port, pipe_path.to_string());

        log_extractor::run(args, shutdown_rx.clone())
            .await
            .expect("log extractor failed");
    });

    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
        .await
        .unwrap();
    let mut sub = nc.subscribe("*").await.unwrap();

    test_setup(&node1.client);

    sleep(Duration::from_secs(1)).await;

    while let Some(msg) = sub.next().await {
        let unwrapped = EventMsg::decode(msg.payload).unwrap();
        if let Some(event) = unwrapped.event {
            if check_event(event) {
                break;
            }
        }
    }

    shutdown_tx.send(true).unwrap();
    log_extractor_handle.await.unwrap();
}

pub fn update_merkle_root(block: &mut Block) -> () {
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

pub fn mine_block(block: &mut Block) {
    let target = block.header.target();
    while !block.header.validate_pow(target).is_ok() {
        block.header.nonce += 1;
    }
}

#[tokio::test]
async fn test_integration_logextractor_log_events() {
    println!("test that we receive log events");

    check(
        vec![],
        |_node1| (),
        |event| {
            match event {
                Event::LogExtractorEvent(r) => {
                    if let Some(ref e) = r.event {
                        match e {
                            _ => {
                                return true;
                            }
                        }
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
async fn test_integration_logextractor_unknown_log_events() {
    println!("test that we receive unknown log events");

    check(
        vec![],
        |_node1| (),
        |event| {
            match event {
                Event::LogExtractorEvent(r) => {
                    if let Some(ref e) = r.event {
                        match e {
                            log_event::Event::UnknownLogMessage(unknown_log_message) => {
                                assert!(unknown_log_message.raw_message.len() > 0);
                                log::info!("UnknownLogMessage {:?}", unknown_log_message);
                                return true;
                            }
                            _ => (),
                        }
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
                Event::LogExtractorEvent(r) => {
                    if let Some(ref e) = r.event {
                        match e {
                            log_event::Event::BlockConnectedLog(block_connected) => {
                                assert!(block_connected.block_height > 0);
                                log::info!("BlockConnectedLog event {}", block_connected);
                                return true;
                            }
                            _ => {}
                        }
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
                Event::LogExtractorEvent(r) => {
                    // When using -logtimemicros=1, the timestamp % 1000 should
                    // (most of the time) be != 0 (or >0). 1 in 1000 cases, it will
                    // be 0, but we test multiple messages.
                    return r.log_timestamp % 1000 > 0;
                }
                _ => panic!("unexpected event {:?}", event),
            };
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
                Event::LogExtractorEvent(r) => {
                    if let Some(ref e) = r.event {
                        match e {
                            log_event::Event::BlockConnectedLog(block_connected) => {
                                assert!(block_connected.block_height > 0);
                                log::info!("BlockConnectedLog event {}", block_connected);
                                return true;
                            }
                            _ => {}
                        }
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
                Event::LogExtractorEvent(r) => {
                    if let Some(ref e) = r.event {
                        match e {
                            log_event::Event::BlockCheckedLog(block_checked) => {
                                assert!(block_checked.block_hash.len() > 0);
                                assert_eq!(block_checked.state, "Valid");
                                log::info!("BlockCheckedLog event {}", block_checked);
                                return true;
                            }
                            _ => {}
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            };
            false
        },
    )
    .await;
}
