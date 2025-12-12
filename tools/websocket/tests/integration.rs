#![cfg(feature = "nats_integration_tests")]

use shared::{
    futures::StreamExt,
    log::{self, warn},
    nats_subjects::Subject,
    prost::Message,
    protobuf::ebpf_extractor::{
        ebpf,
        net_conn::{self, Connection},
        net_msg::{self, message::Msg, Metadata, Ping, Pong},
        Ebpf,
    },
    protobuf::event_msg::{event_msg::PeerObserverEvent, EventMsg},
    rand::{self, Rng},
    simple_logger::SimpleLogger,
    testing::nats_publisher::NatsPublisherForTesting,
    testing::nats_server::NatsServerForTesting,
    tokio::{
        self,
        sync::{watch, Mutex},
        time::sleep,
    },
};

use std::{
    io::ErrorKind,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc, Once, OnceLock,
    },
    time::Duration,
};

use websocket::{error::RuntimeError, Args};

static INIT: Once = Once::new();

static NEXT_WEBSOCKET_PORT: OnceLock<AtomicU16> = OnceLock::new();

fn setup() -> u16 {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();

        let mut rng = rand::rng();

        // choose start ports from the ephemeral port range
        let websocket_start = rng.random_range(49152..65500);
        NEXT_WEBSOCKET_PORT
            .set(AtomicU16::new(websocket_start))
            .unwrap();
    });

    let websocket_port = NEXT_WEBSOCKET_PORT
        .get()
        .unwrap()
        .fetch_add(1, Ordering::SeqCst);
    return websocket_port;
}

fn make_test_args(nats_port: u16, websocket_port: u16) -> Args {
    Args::new(
        format!("127.0.0.1:{}", nats_port),
        format!("127.0.0.1:{}", websocket_port),
        log::Level::Trace,
    )
}

async fn publish_and_check(
    events: &[EventMsg],
    subject: Subject,
    expected: &[&str],
    num_clients: u8,
    disconnect_client: Option<u8>, // which client to disconnect
) {
    let initial_websocket_port = setup();
    let websocket_port: Arc<Mutex<u16>> = Arc::new(Mutex::new(initial_websocket_port));

    let nats_server = NatsServerForTesting::new().await;
    let nats_publisher = NatsPublisherForTesting::new(nats_server.port).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let websocket_port_clone = websocket_port.clone();
    let websocket_handle = tokio::spawn(async move {
        loop {
            let port: u16;
            {
                port = *websocket_port_clone.lock().await;
            }

            let args = make_test_args(nats_server.port, port);
            match websocket::run(args, shutdown_rx.clone()).await {
                Ok(_) => break,
                Err(e) => match e {
                    RuntimeError::Io(e) => match e.kind() {
                        ErrorKind::AddrInUse => {
                            let new_port = NEXT_WEBSOCKET_PORT
                                .get()
                                .unwrap()
                                .fetch_add(1, Ordering::SeqCst);
                            warn!(
                                "Port {} seems to be already in use. Trying port {} next..",
                                port, new_port
                            );
                            let mut port = websocket_port_clone.lock().await;
                            *port = new_port;
                        }
                        _ => panic!("Couldn not start websocket tool: {}", e),
                    },
                    _ => panic!("Couldn not start websocket tool: {}", e),
                },
            }
        }
    });
    // allow the websocket tool to start
    sleep(Duration::from_secs(1)).await;

    let port = websocket_port.lock().await;
    let mut clients = vec![];
    for _ in 0..num_clients {
        let (ws_stream, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}", port))
            .await
            .expect("Should be able to connect to websocket");
        clients.push(ws_stream)
    }

    for event in events.iter() {
        log::debug!("publishing: {:?}", event);
        nats_publisher
            .publish(subject.to_string(), event.encode_to_vec())
            .await;
    }

    if let Some(idx) = disconnect_client {
        clients[idx as usize]
            .close(None)
            .await
            .expect("Should be able to close a client");
    }

    sleep(Duration::from_millis(100)).await;

    assert_eq!(events.len(), expected.len());
    for (i, client) in clients.iter_mut().enumerate() {
        if let Some(idx) = disconnect_client {
            // if we closed this client, we can skip it here as we don't expect it to have all events
            if i == idx as usize {
                continue;
            }
        }
        for expected in expected.iter() {
            if let Some(msg) = client.next().await {
                let msg = msg.unwrap();
                println!("data: {}", msg.to_string());
                assert_eq!(*expected, msg.to_string());
            }
        }
    }

    shutdown_tx.send(true).unwrap();
    websocket_handle.await.unwrap();
}

#[tokio::test]
async fn test_integration_websocket_conn_inbound() {
    println!("test that inbound connections work");

    publish_and_check(&[EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Conn(net_conn::ConnectionEvent {
            event: Some(net_conn::connection_event::Event::Inbound(
                net_conn::InboundConnection {
                    conn: Connection {
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        network: 2,
                        peer_id: 7,
                    },
                    existing_connections: 123,
                },
            )),
        }))
    }))
    .unwrap()], Subject::NetConn, &vec![
        r#"{"EbpfExtractor":{"ebpf_event":{"Conn":{"event":{"Inbound":{"conn":{"peer_id":7,"addr":"127.0.0.1:8333","conn_type":1,"network":2},"existing_connections":123}}}}}}"#,
    ],1, None).await;
}

#[tokio::test]
async fn test_integration_websocket_p2p_message_ping() {
    println!("test that the P2P message via websockets work");

    publish_and_check(
        &[
            EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Msg(net_msg::Message {
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
            .unwrap(),
            EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Msg(net_msg::Message {
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
            .unwrap(),
        ],
        Subject::NetMsg,
        &vec![
            r#"{"EbpfExtractor":{"ebpf_event":{"Msg":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
            r#"{"EbpfExtractor":{"ebpf_event":{"Msg":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#,
        ],
        1,
        None
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_multi_client() {
    println!("test that multiple clients all receive the messages");

    publish_and_check(
        &[
            EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Msg(net_msg::Message {
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
            .unwrap(),
            EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Msg(net_msg::Message {
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
            .unwrap(),
        ],
        Subject::NetMsg,
        &vec![
            r#"{"EbpfExtractor":{"ebpf_event":{"Msg":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"ping","inbound":true,"size":8},"msg":{"Ping":{"value":1}}}}}}"#,
            r#"{"EbpfExtractor":{"ebpf_event":{"Msg":{"meta":{"peer_id":0,"addr":"127.0.0.1:8333","conn_type":1,"command":"pong","inbound":false,"size":8},"msg":{"Pong":{"value":1}}}}}}"#,
        ],
        12,
        None
    )
    .await;
}

#[tokio::test]
async fn test_integration_websocket_closed_client() {
    println!(
        "test that we can close a client connection and the others will still receive the messages"
    );

    publish_and_check(
        &[EventMsg::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Conn(net_conn::ConnectionEvent {
                event: Some(net_conn::connection_event::Event::Outbound(
                    net_conn::OutboundConnection {
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
        .unwrap()],
        Subject::NetConn,
        &vec![
            r#"{"EbpfExtractor":{"ebpf_event":{"Conn":{"event":{"Outbound":{"conn":{"peer_id":11,"addr":"1.1.1.1:48333","conn_type":2,"network":3},"existing_connections":321}}}}}}"#,
        ],
        4,
        Some(2)
    )
    .await;
}
