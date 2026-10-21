#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

mod common;

use common::{configure_node, ipc_socket_path, make_test_args, setup};

use shared::{
    async_nats,
    bitcoin::{Address, Amount, BlockHash, Network, PubkeyHash, hashes::Hash},
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

// 30 second check() timeout.
const TEST_TIMEOUT_SECONDS: u64 = 30;

async fn check<P, D, R>(pred: P, manipulate_node: D) -> (IpcEvent, R)
where
    P: Fn(&IpcEvent) -> bool + Send + 'static,
    D: FnOnce(Arc<bitcoind::BitcoinD>) -> R + Send + 'static,
    R: Send + 'static,
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

            // Allow the extractor to register its ChainNotifications handle
            // before manipulating node state.
            sleep(Duration::from_millis(250)).await;
            let node_jh = std::thread::spawn({
                let node = node.clone();
                move || manipulate_node(node)
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
            let manipulated = node_jh.join().expect("joining the node thread panicked");
            (event, manipulated)
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
    let (event, best_block_hash) = check(
        |e| matches!(e, IpcEvent::BlockTip(_)),
        |node| {
            node.client
                .generate_to_address(1, &regtest_burn_address())
                .expect("generate 1 block");
            node.client
                .get_best_block_hash()
                .expect("getbestblockhash")
                .0
        },
    )
    .await;

    let IpcEvent::BlockTip(tip) = event else {
        unreachable!()
    };
    assert_eq!(tip.height, 1);
    assert_eq!(
        BlockHash::from_slice(&tip.hash).unwrap().to_string(),
        best_block_hash
    );
}

#[tokio::test]
async fn test_integration_block_connected() {
    println!("test that we receive a BlockConnected event when a block is connected");

    let (event, generated) = check(
        |e| matches!(e, IpcEvent::BlockConnected(_)),
        |node| {
            node.client
                .generate_to_address(1, &regtest_burn_address())
                .expect("generate 1 block")
                .0
        },
    )
    .await;

    let IpcEvent::BlockConnected(bc) = event else {
        unreachable!()
    };
    let block = bc.block;
    assert_eq!(block.height, 1);
    assert_eq!(
        BlockHash::from_slice(&block.hash).unwrap().to_string(),
        generated[0]
    );
    let prev_hash = block.prev_hash.expect("block 1 has a previous block");
    assert_eq!(prev_hash.len(), 32);
    assert_eq!(
        BlockHash::from_slice(&prev_hash).unwrap().to_string(),
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", // regtest genesis blockhash
    );
}

#[tokio::test]
async fn test_integration_block_disconnected() {
    println!("test that we receive a BlockDisconnected event when a block is invalidated");

    let (event, invalidated) = check(
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
            to_invalidate
        },
    )
    .await;

    let IpcEvent::BlockDisconnected(bd) = event else {
        unreachable!()
    };
    let block = bd.block;
    assert_eq!(block.height, 2);
    assert_eq!(BlockHash::from_slice(&block.hash).unwrap(), invalidated);
}

#[tokio::test]
async fn test_integration_tx_added_to_mempool() {
    println!("test that we receive a TransactionAddedToMempool event after submitting a tx");

    let (event, ()) = check(
        |e| matches!(e, IpcEvent::TransactionAddedToMempool(_)),
        |node| {
            node.client.create_wallet("default").expect("create wallet");

            let mining_address = node.client.new_address().expect("new address");
            node.client
                .generate_to_address(101, &mining_address)
                .expect("generate 101 blocks to mature a coinbase");

            let dest = regtest_burn_address();
            let amount = Amount::from_btc(1.0).unwrap();
            node.client
                .send_to_address(&dest, amount)
                .expect("send_to_address");
        },
    )
    .await;

    let IpcEvent::TransactionAddedToMempool(t) = event else {
        unreachable!()
    };
    assert_eq!(t.tx.txid.len(), 32);
    assert_eq!(t.tx.wtxid.len(), 32);
    assert!(t.tx.raw.is_some());
}

#[tokio::test]
async fn test_integration_tx_removed_from_mempool() {
    println!(
        "test that we receive a TransactionRemovedFromMempool event when a tx is replaced via RBF"
    );

    let (event, ()) = check(
        |e| matches!(e, IpcEvent::TransactionRemovedFromMempool(_)),
        |node| {
            node.client.create_wallet("default").expect("create wallet");

            let mining_address = node.client.new_address().expect("new address");
            node.client
                .generate_to_address(101, &mining_address)
                .expect("generate 101 blocks to mature a coinbase");

            let dest = regtest_burn_address();
            let amount = Amount::from_btc(1.0).unwrap();
            let original_txid = node
                .client
                .send_to_address(&dest, amount)
                .expect("send_to_address");

            node.client
                .bump_fee(original_txid.txid().expect("send_to_address txid"))
                .expect("bumpfee");
        },
    )
    .await;

    let IpcEvent::TransactionRemovedFromMempool(t) = event else {
        unreachable!()
    };
    assert_eq!(t.tx.txid.len(), 32);
    assert_eq!(t.tx.wtxid.len(), 32);
    assert_eq!(t.reason, "replaced");
}

#[tokio::test]
async fn test_integration_chain_state_flushed() {
    println!("test that we receive a ChainStateFlushed event when the chainstate is flushed");

    let (event, ()) = check(
        |e| matches!(e, IpcEvent::ChainStateFlushed(_)),
        |node| {
            // gettxoutsetinfo flushes the chainstate to disk before reading it.
            node.client.get_tx_out_set_info().expect("gettxoutsetinfo");
        },
    )
    .await;

    let IpcEvent::ChainStateFlushed(f) = event else {
        unreachable!()
    };
    assert!(f.role.validated);
    assert!(!f.role.historical);
    assert!(!f.locator.is_empty());
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
