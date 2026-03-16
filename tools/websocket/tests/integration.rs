#![cfg(feature = "nats_integration_tests")]

use shared::{
    futures::{stream, SinkExt, StreamExt},
    log,
    nats_subjects::Subject,
    nats_util::NatsArgs,
    prost::Message,
    protobuf::{
        ebpf_extractor::{
            connection::{self, Connection},
            ebpf,
            mempool::{self, Added},
            message::{self, message_event::Msg, Metadata, Ping, Pong},
            validation::{self, BlockConnected},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
    },
    simple_logger::SimpleLogger,
    testing::{nats_publisher::NatsPublisherForTesting, nats_server::NatsServerForTesting},
    tokio::{
        self, select,
        sync::{oneshot, watch},
        time::{sleep, timeout},
    },
};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

use std::{sync::Once, time::Duration};

use websocket::{Args, ClientSubscriptions, ClientSubscriptionsEbpf};

const SUBSCRIBE_NONE: ClientSubscriptions = ClientSubscriptions {
    ebpf: ClientSubscriptionsEbpf {
        messages: false,
        mempool: false,
        validation: false,
        connections: false,
    },
    p2p: false,
    log: false,
    rpc: false,
    ipc: false,
};

const SUBSCRIBE_ALL: ClientSubscriptions = ClientSubscriptions {
    ebpf: ClientSubscriptionsEbpf {
        messages: true,
        mempool: true,
        validation: true,
        connections: true,
    },
    p2p: true,
    log: true,
    rpc: true,
    ipc: true,
};

#[derive(Debug, Clone)]
struct ClientConfig {
    subscriptions: ClientSubscriptions,
    expected_events: Vec<&'static str>,
    disconnect: bool, // whether to disconnect this client before receiving messages
}

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

fn make_test_args(nats_port: u16) -> Args {
    Args::new(
        NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        "127.0.0.1:0".to_string(),
        log::Level::Trace,
    )
}

/// Creates a marker event matching the first active subscription type in the
/// given subscriptions. Returns `(subject, payload, detect)` where `detect` is
/// a substring that uniquely identifies this marker in the JSON-serialized
/// websocket message. Returns `None` if no subscriptions are active.
/// Only covers types exercised by tests: messages and mempool.
fn marker_for_subscriptions(
    marker: &str,
    client_index: usize,
    subs: &ClientSubscriptions,
) -> Option<(String, Vec<u8>, String)> {
    let (subject, ebpf_event, detect) = if subs.ebpf.messages {
        (
            Subject::NetMsg,
            ebpf::EbpfEvent::Message(message::MessageEvent {
                meta: Metadata {
                    peer_id: 0,
                    addr: marker.to_string(),
                    conn_type: 0,
                    command: "marker".to_string(),
                    inbound: false,
                    size: 0,
                },
                msg: Some(Msg::Ping(Ping { value: 0 })),
            }),
            marker.to_string(),
        )
    } else if subs.ebpf.mempool {
        // Mempool events have no string fields, so we use a unique fee value
        // derived from the client index as the detection substring.
        let fee: i64 = 21212121 + client_index as i64;
        (
            Subject::Mempool,
            ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
                event: Some(mempool::mempool_event::Event::Added(Added {
                    txid: vec![],
                    vsize: 0,
                    fee,
                })),
            }),
            fee.to_string(),
        )
    } else {
        return None;
    };

    let event = Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf_event),
    }))
    .unwrap();

    Some((subject.to_string(), event.encode_to_vec(), detect))
}

/// Publishes a marker event to NATS and waits for it to arrive on the given
/// websocket client stream, proving the full NATS -> server -> client path is
/// live. The marker is re-published on a short interval because early
/// publications may arrive before the server has fully registered the client.
/// Panics on timeout.
async fn wait_for_marker<S>(
    publisher: &NatsPublisherForTesting,
    marker: &str,
    subject: &str,
    payload: &[u8],
    detect: &str,
    client: &mut S,
) where
    S: StreamExt<Item = Result<TungsteniteMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let mut marker_seen = false;
    select! {
        _ = sleep(Duration::from_secs(5)) => {
            panic!("timed out waiting for pipeline-ready marker '{marker}'");
        }
        _ = async {
            loop {
                publisher
                    .publish(subject.to_string(), payload.to_vec())
                    .await;
                log::debug!("published pipeline-ready marker '{marker}'");

                // Drain all available messages before re-publishing. Earlier
                // clients' markers may have accumulated in this stream.
                loop {
                    match tokio::time::timeout(Duration::from_millis(50), client.next()).await {
                        Ok(Some(msg)) => {
                            let msg = msg.expect("websocket message should be valid");
                            if msg.to_string().contains(detect) {
                                log::info!("received pipeline-ready marker: {marker}");
                                marker_seen = true;
                                return;
                            }
                            // Not our marker; keep draining.
                        }
                        Ok(None) => panic!(
                            "websocket stream closed before pipeline-ready marker '{marker}' arrived"
                        ),
                        Err(_) => break, // no more messages, re-publish
                    }
                }
            }
        } => {}
    }
    assert!(
        marker_seen,
        "websocket stream closed before pipeline-ready marker '{marker}' arrived"
    );

    // Drain any extra copies of the marker that arrived while re-publishing.
    // No real test events have been published yet, so everything here is a
    // marker (ours or another client's from a prior iteration).
    sleep(Duration::from_millis(50)).await;
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(10), client.next()).await {
        let _ = msg.expect("websocket message should be valid");
    }
}

async fn publish_and_check_simple(
    events: &[(Subject, Event)],
    expected_events: Vec<&'static str>,
    num_clients: Option<u8>,
) {
    let num_clients = num_clients.unwrap_or(1);
    let clients = vec![
        ClientConfig {
            subscriptions: SUBSCRIBE_ALL.clone(),
            expected_events: expected_events.to_vec(),
            disconnect: false,
        };
        num_clients as usize
    ];

    publish_and_check(events, clients.as_slice()).await;
}

async fn publish_and_check(events: &[(Subject, Event)], clients: &[ClientConfig]) {
    setup();

    let nats_server = NatsServerForTesting::new(&[]).await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();
    let args = make_test_args(nats_server.port);
    let websocket_handle = tokio::spawn(async move {
        websocket::run(args, shutdown_rx, Some(bound_addr_tx))
            .await
            .expect("websocket tool should start successfully");
    });

    let bound_addr = bound_addr_rx
        .await
        .expect("Should receive bound address from websocket tool");

    let mut clients_stream = vec![];
    for client_config in clients {
        let (ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://{}", bound_addr))
            .await
            .expect("Should be able to connect to websocket");
        let (mut outgoing, incoming) = ws_stream.split();
        outgoing
            .send(TungsteniteMessage::Text(
                serde_json::to_string(&client_config.subscriptions)
                    .unwrap()
                    .into(),
            ))
            .await
            .expect("Should be able to send subscription message");
        clients_stream.push((outgoing, incoming));
    }

    // Pipeline readiness barrier: wait for EVERY subscribing client to
    // confirm the full NATS -> websocket server -> client path is live.
    // Each client is independently inserted into the server's broadcast map
    // and has its subscriptions applied independently, so one
    // client receiving a marker does NOT prove the others are registered.
    // The marker event type must match the client's subscription because
    // broadcast_to_clients() filters by protobuf variant.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for (i, client_config) in clients.iter().enumerate() {
        if client_config.disconnect {
            continue;
        }
        let marker = format!("PIPELINE_READY:{nanos}:{i}");
        if let Some((subject, payload, detect)) =
            marker_for_subscriptions(&marker, i, &client_config.subscriptions)
        {
            wait_for_marker(
                &nats_publisher,
                &marker,
                &subject,
                &payload,
                &detect,
                &mut clients_stream[i].1,
            )
            .await;
        }
    }

    // Final drain: flush any markers that leaked to other clients during
    // the sequential readiness checks above.
    sleep(Duration::from_millis(50)).await;
    for (i, client_config) in clients.iter().enumerate() {
        if client_config.disconnect {
            continue;
        }
        let incoming = &mut clients_stream[i].1;
        while let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(10), incoming.next()).await
        {
            let _ = msg.expect("websocket message should be valid");
        }
    }

    for (subject, event) in events.iter() {
        log::debug!("publishing: {:?}", event);
        nats_publisher
            .publish(subject.to_string(), event.encode_to_vec())
            .await;
    }

    for (i, client_config) in clients.iter().enumerate() {
        if client_config.disconnect {
            let outgoing = &mut clients_stream[i].0;
            outgoing
                .close()
                .await
                .expect("Should be able to close a client");
        }
    }

    stream::iter(clients_stream)
        .enumerate()
        .map(async |(i, (_, mut incoming))| {
            let client_config = &clients[i];
            if client_config.disconnect {
                // if we closed this client, we can skip it here as we don't expect it to have all events
                return;
            }

            let mut messages = vec![];
            timeout(Duration::from_secs(1), async {
                while let Some(msg) = incoming.next().await {
                    messages.push(msg.unwrap());
                }
            })
            .await
            .unwrap_or(());

            assert_eq!(client_config.expected_events.len(), messages.len()); // not less, not more

            for (i, expected) in client_config.expected_events.iter().enumerate() {
                let msg = &messages[i];
                assert_eq!(*expected, msg.to_string());
            }
        })
        .buffer_unordered(clients.len())
        .collect::<Vec<_>>()
        .await;

    shutdown_tx.send(true).unwrap();
    websocket_handle.await.unwrap();
}

async fn custom_message_check(message: &str) {
    setup();

    let nats_server = NatsServerForTesting::new(&[]).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (bound_addr_tx, bound_addr_rx) = oneshot::channel();
    let args = make_test_args(nats_server.port);
    let websocket_handle = tokio::spawn(async move {
        websocket::run(args, shutdown_rx, Some(bound_addr_tx))
            .await
            .expect("websocket tool should start successfully");
    });

    let bound_addr = bound_addr_rx
        .await
        .expect("Should receive bound address from websocket tool");

    let (ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://{}", bound_addr))
        .await
        .expect("Should be able to connect to websocket");
    let (mut outgoing, mut incoming) = ws_stream.split();

    outgoing
        .send(TungsteniteMessage::Text(message.into()))
        .await
        .expect("Should be able to send custom message");

    let msg = incoming
        .next()
        .await
        .expect("No message received")
        .expect("Error in message");
    assert!(
        matches!(msg, TungsteniteMessage::Close(_)),
        "Expected Close message, got {:?}",
        msg
    );

    shutdown_tx.send(true).unwrap();
    websocket_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_websocket_conn_inbound() {
    println!("test that inbound connections work");

    publish_and_check(
        &[(
            Subject::NetConn,
            Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                    event: Some(connection::connection_event::Event::Inbound(
                        connection::InboundConnection {
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
            .unwrap(),
        )],
        &[ClientConfig {
            subscriptions: SUBSCRIBE_ALL.clone(),
            expected_events: vec![
                r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Inbound":{"conn":{"peer_id":7,"addr":"127.0.0.1:8333","conn_type":1,"network":2},"existing_connections":123}}}}}}"#,
            ],
            disconnect: false,
        }],
    ).await;
}

#[tokio::test]
async fn test_integration_websocket_p2p_message_ping() {
    println!("test that the P2P message via websockets work");

    publish_and_check(
        &[
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1 })),
                }))
            }))
            .unwrap()),
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "pong".to_string(),
                        inbound: false,
                        size: 8,
                    },
                    msg: Some(Msg::Pong(Pong { value: 1 })),
                }))
            }))
            .unwrap(),)
        ],
        &[
          ClientConfig {
              subscriptions: SUBSCRIBE_ALL.clone(),
              expected_events: vec![
                  r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
                  r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#],
              disconnect: false,
          },
        ]
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_multi_client() {
    println!("test that multiple clients all receive the messages");

    publish_and_check_simple(
        &[
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 1 })),
                }))
            }))
            .unwrap()),
            (Subject::NetMsg, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent  {
                    meta: Metadata {
                        peer_id: 0,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "pong".to_string(),
                        inbound: false,
                        size: 8,
                    },
                    msg: Some(Msg::Pong(Pong { value: 1 })),
                }))
            }))
            .unwrap()),
        ],
        vec![r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
            r#"{"EbpfExtractor":{"ebpf_event":{"Message":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#],
        Some(12),
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_closed_client() {
    println!(
        "test that we can close a client connection and the others will still receive the messages"
    );

    publish_and_check(
        &[(Subject::NetConn, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                event: Some(connection::connection_event::Event::Outbound(
                    connection::OutboundConnection {
                        conn: Connection {
                            addr: "1.1.1.1:48333".to_string(),
                            conn_type: 2,
                            network: 3,
                            peer_id: 11,
                        },
                        existing_connections: 321,
                    },
                )),
            }))
        }))
        .unwrap())],
        &[
            ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![
                    r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Outbound":{"conn":{"peer_id":11,"addr":"1.1.1.1:48333","conn_type":2,"network":3},"existing_connections":321}}}}}}"#,
                ],
                disconnect: false,
            },
              ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![],
                disconnect: true,
            },
              ClientConfig {
                subscriptions: SUBSCRIBE_ALL.clone(),
                expected_events: vec![
                    r#"{"EbpfExtractor":{"ebpf_event":{"Connection":{"event":{"Outbound":{"conn":{"peer_id":11,"addr":"1.1.1.1:48333","conn_type":2,"network":3},"existing_connections":321}}}}}}"#,
                ],
                disconnect: false,
            },
        ],
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_specific_subjects() {
    println!("test that we can subscribe to specific subjects and only receive those events");

    let mut subscriptions = SUBSCRIBE_NONE.clone();
    subscriptions.ebpf.mempool = true;

    publish_and_check(
        &[
            (Subject::Mempool, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
                    event: Some(mempool::mempool_event::Event::Added(Added {
                        txid: vec![76, 70, 231],
                        vsize: 175,
                        fee: 358,
                    })),
                }))
            }))
            .unwrap()),
            (Subject::Validation, Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Validation(validation::ValidationEvent {
                    event: Some(validation::validation_event::Event::BlockConnected(BlockConnected {
                        hash: vec![1, 2, 3, 4, 5],
                        height: 800000,
                        transactions: 2500,
                        inputs: 5000,
                        sigops: 20000,
                        connection_time: 1500000000,
                    })),
                }))
            }))
            .unwrap()),
        ],
        &[
              ClientConfig {
                  subscriptions,
                  expected_events: vec![
                      r#"{"EbpfExtractor":{"ebpf_event":{"Mempool":{"event":{"Added":{"txid":[76,70,231],"vsize":175,"fee":358}}}}}}"#,
                  ],
                  disconnect: false,
              },
              ClientConfig {
                  subscriptions: SUBSCRIBE_NONE.clone(),
                  expected_events: vec![],
                  disconnect: false,
              },
        ]
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_invalid_message_disconnect() {
    println!("Check that we disconnect on invalid, empty, and large messages");
    custom_message_check("").await;
    custom_message_check("aaaaaaa").await;
    custom_message_check(&"a".repeat(513)).await;
}
