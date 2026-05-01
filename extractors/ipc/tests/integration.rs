#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

mod common;

use common::{configure_node, ipc_socket_path, make_test_args, setup};

use shared::{
    async_nats,
    bitcoin::{Address, BlockHash, Network, PubkeyHash, hashes::Hash},
    bitcoind,
    futures::StreamExt,
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        ipc_extractor::ipc::IpcEvent,
    },
    testing::nats_server::NatsServerForTesting,
    tokio::{self, sync::watch, task::LocalSet, time::sleep},
};
use std::sync::Arc;
use std::time::Duration;

// 5 second check() timeout.
const TEST_TIMEOUT_SECONDS: u64 = 5;

async fn check<P, D>(pred: P, drive: D) -> IpcEvent
where
    P: Fn(&IpcEvent) -> bool + Send + 'static,
    D: FnOnce(Arc<bitcoind::BitcoinD>) + Send + 'static,
{
    setup();
    let node = Arc::new(configure_node());
    let nats_server = NatsServerForTesting::new(&[]).await;

    let args = make_test_args(nats_server.port, ipc_socket_path(&node));

    LocalSet::new()
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let mut extractor =
                tokio::task::spawn_local(ipc_extractor::run(args, shutdown_rx, None));

            let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
                .await
                .unwrap();
            let mut sub = nc.subscribe("*").await.unwrap();

            // Allow the extractor to register its ChainNotifications subscription
            // before driving node state.
            sleep(Duration::from_millis(250)).await;
            std::thread::spawn({
                let node = node.clone();
                move || drive(node)
            });

            let event = tokio::select! {
                _ = sleep(Duration::from_secs(TEST_TIMEOUT_SECONDS)) => {
                    panic!("timed out waiting for matching IPC event");
                }
                ev = await_ipc_event(&mut sub, pred) => ev,
                res = &mut extractor => {
                    panic!("ipc_extractor stopped unexpectedly: {:?}", res);
                }
            };

            let _ = shutdown_tx.send(true);
            let _ = extractor.await;
            event
        })
        .await
}

fn regtest_burn_address() -> Address {
    Address::p2pkh(PubkeyHash::from_byte_array([0u8; 20]), Network::Regtest)
}

async fn await_ipc_event<F>(sub: &mut async_nats::Subscriber, pred: F) -> IpcEvent
where
    F: Fn(&IpcEvent) -> bool,
{
    while let Some(msg) = sub.next().await {
        let Ok(envelope) = Event::decode(msg.payload) else {
            continue;
        };
        let Some(PeerObserverEvent::IpcExtractor(ipc)) = envelope.peer_observer_event else {
            continue;
        };
        let Some(e) = ipc.ipc_event else { continue };
        if pred(&e) {
            return e;
        }
    }
    panic!("subscription ended without matching event");
}

#[tokio::test]
async fn test_integration_ipc() {
    let event = check(
        |e| matches!(e, IpcEvent::BlockTip(_)),
        |node| {
            node.client
                .generate_to_address(1, &regtest_burn_address())
                .expect("generate 1 block");
        },
    )
    .await;

    let IpcEvent::BlockTip(tip) = event else {
        unreachable!()
    };
    assert_eq!(tip.height, 1);
    assert_eq!(tip.hash.len(), 32);
}

#[tokio::test]
async fn test_integration_block_connected() {
    println!("test that we receive a BlockConnected event when a block is connected");

    let event = check(
        |e| matches!(e, IpcEvent::BlockConnected(_)),
        |node| {
            node.client
                .generate_to_address(1, &regtest_burn_address())
                .expect("generate 1 block");
        },
    )
    .await;

    let IpcEvent::BlockConnected(bc) = event else {
        unreachable!()
    };
    let block = bc.block;
    assert_eq!(block.height, 1);
    assert_eq!(block.hash.len(), 32);
    assert_eq!(block.prev_hash.len(), 32);
    assert_eq!(
        BlockHash::from_slice(&block.prev_hash).unwrap().to_string(),
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", // regtest genesis blockhash
    );
}

#[tokio::test]
async fn test_integration_block_disconnected() {
    println!("test that we receive a BlockDisconnected event when a block is invalidated");

    let event = check(
        |e| matches!(e, IpcEvent::BlockDisconnected(_)),
        |node| {
            let block_hashes = node
                .client
                .generate_to_address(2, &regtest_burn_address())
                .expect("generate 2 blocks")
                .into_model()
                .expect("parse block hashes");
            let to_invalidate = block_hashes.0[1];
            node.client
                .invalidate_block(to_invalidate)
                .expect("invalidate block 2");
        },
    )
    .await;

    let IpcEvent::BlockDisconnected(bd) = event else {
        unreachable!()
    };
    let block = bd.block;
    assert_eq!(block.height, 2);
    assert_eq!(block.hash.len(), 32);
}

#[tokio::test]
async fn test_integration_ipc_node_shutdown() {
    println!("test that the ipc-extractor shuts down when the node is stopped");

    let _ = check(
        |_| true,
        |node| {
            // Should trigger a clean shutdown and not throw unexpectedly
            node.client.stop().unwrap();
        },
    )
    .await;
}
