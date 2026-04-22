#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

mod common;

use common::{
    EnabledRPCsInTest, get_available_port, make_test_args, setup, setup_two_connected_nodes,
};

use shared::{
    async_nats,
    bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        consensus, hashes::Hash, hex::DisplayHex, transaction,
    },
    corepc_node,
    futures::StreamExt,
    prost::Message,
    protobuf::{
        event::{Event, event::PeerObserverEvent},
        rpc_extractor::{
            FeeEstimateMode,
            rpc::RpcEvent::{
                Addrman, AddrmanInfo, BlockchainInfo, ChainTxStats, EstimateSmartFee, MemoryInfo,
                MempoolInfo, NetTotals, NetworkInfo, OrphanTxs, PeerInfos, Uptime,
            },
        },
    },
    testing::{REGTEST_ADDRESS, nats_server::NatsServerForTesting},
    tokio::{
        self, select,
        sync::watch,
        time::{Duration, sleep},
    },
};

use std::collections::HashMap;

// 5 second check() timeout.
const TEST_TIMEOUT_SECONDS: u64 = 5;

async fn check(
    rpcs: EnabledRPCsInTest,
    test_setup: fn(&corepc_node::Node, &corepc_node::Node),
    check_expected: fn(PeerObserverEvent) -> (),
) {
    setup();
    let (node1, node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics_port = get_available_port();

    let url = node1.rpc_url().replace("http://", "");
    let cookie_file_path = node1.params.cookie_file.display().to_string();

    sleep(Duration::from_secs(1)).await;
    test_setup(&node1, &node2);
    sleep(Duration::from_secs(1)).await;

    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            url,
            cookie_file_path,
            format!("127.0.0.1:{}", metrics_port),
            rpcs,
        );
        rpc_extractor::run(args, shutdown_rx.clone())
            .await
            .expect("rpc extractor failed");
    });

    let nc = async_nats::connect(format!("127.0.0.1:{}", nats_server.port))
        .await
        .unwrap();
    let mut sub = nc.subscribe("*").await.unwrap();

    select! {
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
    }

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_rpc_getpeerinfo() {
    println!("test that we receive getpeerinfo RPC events");

    check(
        EnabledRPCsInTest {
            getpeerinfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| {
            match event {
                PeerObserverEvent::RpcExtractor(r) => {
                    if let Some(ref e) = r.rpc_event {
                        match e {
                            PeerInfos(p) => {
                                // we expect 1 peer to be connected
                                assert_eq!(p.infos.len(), 1);
                                let peer = p.infos.first().expect("we have expactly one peer here");
                                assert_eq!(peer.connection_type, "inbound");
                            }
                            _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                        }
                    }
                }
                _ => panic!("unexpected event {:?}", event),
            }
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getmempoolinfo() {
    println!("test that we receive getmempoolinfo RPC events");

    check(
        EnabledRPCsInTest {
            getmempoolinfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        MempoolInfo(info) => {
                            assert!(info.loaded);
                            assert_eq!(info.size, 0);
                            assert_eq!(info.usage, 0);
                            assert_eq!(info.bytes, 0);
                            assert_eq!(info.total_fee, 0.0);
                            assert_eq!(info.max_mempool, 300000000);
                            assert_eq!(info.mempoolminfee, 0.1);
                            assert_eq!(info.minrelaytxfee, 0.1);
                            assert_eq!(info.incrementalrelayfee, 0.1);

                            assert_eq!(info.unbroadcastcount, 0);
                            assert!(info.fullrbf);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_uptime() {
    println!("test that we receive uptime RPC events");

    check(
        EnabledRPCsInTest {
            uptime: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        Uptime(uptime_seconds) => {
                            // Uptime should be a positive number
                            assert!(*uptime_seconds > 0);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getnettotals() {
    println!("test that we receive getnettotals RPC events");

    check(
        EnabledRPCsInTest {
            getnettotals: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        NetTotals(net_totals) => {
                            assert!(net_totals.time_millis > 0);
                            assert!(net_totals.total_bytes_received > 0);
                            assert!(net_totals.total_bytes_sent > 0);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getmemoryinfo() {
    println!("test that we receive getmemoryinfo RPC events");

    check(
        EnabledRPCsInTest {
            getmemoryinfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        MemoryInfo(info) => {
                            assert!(info.total > 0);
                            assert!(info.used <= info.total);
                            assert!(info.locked <= info.total);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getaddrmaninfo() {
    println!("test that we receive getaddrmaninfo RPC events");

    check(
        EnabledRPCsInTest {
            getaddrmaninfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        AddrmanInfo(info) => {
                            assert!(!info.networks.is_empty());

                            if let Some(all_nets) = info.networks.get("all_networks") {
                                assert_eq!(
                                    all_nets.total,
                                    all_nets.new + all_nets.tried,
                                    "all_networks: total should equal new + tried"
                                );
                            }

                            for (network, data) in &info.networks {
                                assert_eq!(
                                    data.total,
                                    data.new + data.tried,
                                    "Network {}: total should equal new + tried",
                                    network
                                );
                            }
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getchaintxstats() {
    println!("test that we receive getchaintxstats RPC events");

    check(
        EnabledRPCsInTest {
            getchaintxstats: true,
            ..Default::default()
        },
        |node1, _| {
            // Note: window_tx_count, window_interval, and tx_rate
            // are only present when window_block_count > 0, which
            // requires mining a few blocks blocks.
            node1
                .client
                .generate_to_address(201, &REGTEST_ADDRESS)
                .expect("failed to generate to address");
        },
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        ChainTxStats(stats) => {
                            assert!(stats.time > 1770395781);
                            assert_eq!(stats.tx_count, 202);
                            assert!(!stats.window_final_block_hash.is_empty());
                            assert_eq!(stats.window_final_block_height, 201);
                            assert_eq!(stats.window_block_count, 200);
                            assert_eq!(stats.window_tx_count, Some(200));
                            assert_eq!(stats.window_interval, Some(34));
                            assert_eq!(stats.tx_rate, Some(5.882352941176471));
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getnetworkinfo() {
    println!("test that we receive getnetworkinfo RPC events");

    check(
        EnabledRPCsInTest {
            getnetworkinfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        NetworkInfo(info) => {
                            // Version checks
                            assert!(info.version > 0);
                            assert!(
                                info.protocol_version >= 70001,
                                "Protocol version should be modern"
                            );
                            assert!(
                                info.subversion.starts_with("/Satoshi:"),
                                "Subversion should start with /Satoshi:"
                            );

                            // Network checks - must include at least ipv4
                            assert!(!info.networks.is_empty());
                            assert!(
                                info.networks.iter().any(|n| n.name == "ipv4"),
                                "Should include ipv4 network"
                            );

                            // Connection checks - should have at least 1 (the test node)
                            assert!(info.connections >= 1, "Should have at least 1 connection");

                            // Fee checks - must be positive
                            assert!(info.relay_fee > 0.0, "Relay fee should be positive");
                            assert!(
                                info.incremental_fee > 0.0,
                                "Incremental fee should be positive"
                            );
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getblockchaininfo() {
    println!("test that we receive getblockchaininfo RPC events");

    check(
        EnabledRPCsInTest {
            getblockchaininfo: true,
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        BlockchainInfo(info) => {
                            // Chain should be regtest for integration tests
                            assert_eq!(info.chain, "regtest", "Chain should be regtest");

                            // Bestblockhash should be a non-empty string (64 hex chars)
                            assert_eq!(
                                info.bestblockhash.len(),
                                64,
                                "Best block hash should be 64 hex characters"
                            );

                            // Difficulty should be > 0
                            assert!(info.difficulty > 0.0, "Difficulty should be positive");

                            // Verification progress should be between 0 and 1
                            assert!(
                                info.verificationprogress >= 0.0
                                    && info.verificationprogress <= 1.0,
                                "Verification progress should be between 0 and 1"
                            );

                            // Size on disk should be > 0
                            assert!(info.size_on_disk > 0, "Size on disk should be positive");

                            // In regtest, pruned should be false by default
                            assert!(!info.pruned, "Regtest should not be pruned by default");
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getorphantxs() {
    println!("test that we receive getorphantxs RPC events");

    check(
        EnabledRPCsInTest {
            getorphantxs: true,
            ..Default::default()
        },
        |node1, node2| {
            // Generate a couple of orphan transactions by spending from non-existing UTXOs.
            const NUM_ORPHANS: u8 = 3;
            let orphans: Vec<Transaction> = (0..NUM_ORPHANS)
                .map(|i| Transaction {
                    version: transaction::Version::ONE,
                    lock_time: absolute::LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: OutPoint {
                            txid: Txid::from_raw_hash(Txid::from_byte_array([i; 32]).into()),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::new(),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(100_000),
                        script_pubkey: REGTEST_ADDRESS.script_pubkey(),
                    }],
                })
                .collect();

            // The receiving node needs to be out of IBD to start accepting transactions.
            node1
                .client
                .generate_to_address(1, &REGTEST_ADDRESS)
                .expect("failed to generate to address");

            // node1 is peer=0 of node2
            const PEER_ID: u64 = 0;
            for orphan in orphans.iter() {
                let tx_bytes = consensus::encode::serialize(orphan);
                let tx_hex: String = tx_bytes.as_hex().to_string();
                // HACK: We should use sendmsgtopeer directly but it's not implemented yet.
                node2
                    .client
                    .call::<HashMap<String, String>>(
                        "sendmsgtopeer",
                        &[PEER_ID.into(), "tx".into(), tx_hex.into()],
                    )
                    .unwrap();
            }
        },
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        OrphanTxs(result) => {
                            assert_eq!(result.orphans.len(), 3);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_getrawaddrman() {
    println!("test that we receive getrawaddrman RPC events");

    check(
        EnabledRPCsInTest {
            getrawaddrman: true,
            ..Default::default()
        },
        |node1, _node2| {
            node1
                .client
                .add_peer_address("1.2.3.4", 1234)
                .expect("addpeeraddress");
        },
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        Addrman(addrman) => {
                            for (_, bucket) in addrman.new.iter() {
                                for (_, entry) in bucket.entries.iter() {
                                    assert_eq!(entry.address, "1.2.3.4");
                                    assert_eq!(entry.port, 1234);
                                }
                            }
                            assert_eq!(
                                addrman
                                    .new
                                    .iter()
                                    .fold(0, |acc, bucket| acc + bucket.1.entries.len()),
                                1
                            );
                            assert_eq!(
                                addrman
                                    .tried
                                    .iter()
                                    .fold(0, |acc, bucket| acc + bucket.1.entries.len()),
                                0
                            );
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
#[should_panic(expected = "timed out waiting for check() to complete")]
async fn test_integration_rpc_testsshouldtimeout() {
    println!("test that we timeout long running tests");

    check(
        EnabledRPCsInTest {
            ..Default::default()
        },
        |_, _| (),
        |event| match event {
            PeerObserverEvent::RpcExtractor(_) => {
                panic!("We should never receive an event here.")
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}

#[tokio::test]
async fn test_integration_rpc_estimatesmartfee() {
    println!("test that we receive estimatesmartfee RPC events");

    check(
        EnabledRPCsInTest {
            estimatesmartfee: true,
            ..Default::default()
        },
        |node1, _node2| {
            // Mine to a wallet-owned address so node1 has spendable UTXOs
            let miner_address = node1
                .client
                .new_address()
                .expect("failed to get new address");
            node1
                .client
                .generate_to_address(101, &miner_address)
                .expect("failed to generate to address");

            // generate some transactions to create enough data for fee estimation
            let recipient = REGTEST_ADDRESS.to_string();
            for _ in 0..20 {
                node1
                    .client
                    .call::<String>("sendtoaddress", &[recipient.clone().into(), "1".into()])
                    .expect("failed to send to address");

                node1
                    .client
                    .generate_to_address(1, &miner_address)
                    .expect("failed to generate to address");
            }
        },
        |event| match event {
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(ref e) = r.rpc_event {
                    match e {
                        EstimateSmartFee(result) => {
                            // Fee rate most of the time is 0.0001_0000 on this scenario, but sometimes is greater
                            assert!(result.fee_rate >= Some(10.0));
                            assert!(result.fee_rate < Some(10.1));

                            let expected_combinations = [
                                (1, FeeEstimateMode::Economical as i32),
                                (1, FeeEstimateMode::Conservative as i32),
                                (6, FeeEstimateMode::Economical as i32),
                                (6, FeeEstimateMode::Conservative as i32),
                                (144, FeeEstimateMode::Economical as i32),
                                (144, FeeEstimateMode::Conservative as i32),
                            ];
                            let found = expected_combinations.iter().any(|(blocks, mode)| {
                                *blocks == result.requested_blocks && *mode == result.mode
                            });

                            assert!(found);
                        }
                        _ => panic!("unexpected RPC data {:?}", r.rpc_event),
                    }
                }
            }
            _ => panic!("unexpected event {:?}", event),
        },
    )
    .await;
}
