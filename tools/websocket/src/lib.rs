#![cfg_attr(feature = "strict", deny(warnings))]

use shared::clap::Parser;
use shared::futures::{stream::SplitSink, SinkExt, StreamExt};
use shared::log;
use shared::nats_util::NatsArgs;
use shared::prost::Message;
use shared::protobuf::{
    ebpf_extractor::ebpf,
    event::{self, event::PeerObserverEvent},
};
use shared::serde::{Deserialize, Serialize};
use shared::{
    clap, nats_util,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::{oneshot, watch, Mutex},
    },
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_tungstenite::{
    accept_async, tungstenite::protocol::Message as TungsteniteMessage, WebSocketStream,
};

pub mod error;

/// A peer-observer tool that sends out all events on a websocket
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// The websocket address the tool listens on.
    #[arg(short, long, default_value = "127.0.0.1:47482")]
    pub websocket_address: String,

    /// The log level the took should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,
}

impl Args {
    pub fn new(nats: NatsArgs, websocket_address: String, log_level: log::Level) -> Self {
        Self {
            nats,
            websocket_address,
            log_level,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "shared::serde", default)]
pub struct ClientSubscriptionsEbpf {
    pub messages: bool,
    pub mempool: bool,
    pub validation: bool,
    pub connections: bool,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "shared::serde", default)]
pub struct ClientSubscriptions {
    pub ebpf: ClientSubscriptionsEbpf,
    pub p2p: bool,
    pub log: bool,
    pub rpc: bool,
    pub ipc: bool,
}

struct Client {
    outgoing: SplitSink<WebSocketStream<TcpStream>, TungsteniteMessage>,
    subscriptions: ClientSubscriptions,
}

type Clients = Arc<Mutex<HashMap<SocketAddr, Client>>>;

pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
    bound_addr_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<(), error::RuntimeError> {
    let nc = nats_util::prepare_connection(&args.nats)?
        .connect(&args.nats.address)
        .await?;
    log::info!("Connected to NATS-server at {}", args.nats.address);
    let mut sub = nc.subscribe("*").await?;
    nc.flush().await?;

    let clients = Arc::new(Mutex::new(HashMap::new()));

    // Spawn a thread to handle NATS messages and broadcast to WebSocket clients
    {
        let clients = Arc::clone(&clients);
        tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                match event::Event::decode(msg.payload) {
                    Ok(event) => {
                        if let Some(event) = event.peer_observer_event {
                            broadcast_to_clients(&event, &clients).await;
                        }
                    }
                    Err(e) => log::error!("Could not deserialize protobuf message: {}", e),
                };
            }
        });
    }

    log::debug!("Starting websocket server on {}...", args.websocket_address);
    let server = TcpListener::bind(args.websocket_address).await?;
    let local_addr = server.local_addr()?;
    log::info!("Started websocket server on {}", local_addr);

    // Notify the caller of the actual bound address (used in tests with port 0).
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(local_addr);
    }

    // Accept WebSocket clients
    loop {
        let clients = Arc::clone(&clients);
        shared::tokio::select! {
            accept_result = server.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, addr, clients).await {
                                log::warn!("Could not handle client: {}", e);
                            };
                        });
                    }
                    Err(e) => {
                        log::warn!("Could not accept connection on socket: {}", e);
                    }
                }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("websocket tool received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_client(
    stream: TcpStream,
    addr: SocketAddr,
    clients: Clients,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let websocket = accept_async(stream).await?;

    let (outgoing, mut incoming) = websocket.split();

    let client = Client {
        outgoing,
        // Clients start without any subscriptions
        subscriptions: ClientSubscriptions::default(),
    };

    clients.lock().await.insert(addr, client);

    log::info!("Client '{}' connected", addr);

    while let Some(msg) = incoming.next().await {
        match msg {
            Ok(m) => {
                match m {
                    TungsteniteMessage::Close(_) => {
                        // Remove the client from the shared list if the connection is closed
                        clients.lock().await.remove(&addr);
                        break;
                    }
                    TungsteniteMessage::Text(text) => {
                        let truncated_text: String = text.chars().take(100).collect();
                        match text.len() {
                            0 => {
                                log::warn!(
                                    "Received empty message from client {addr}. Disconnecting."
                                )
                            }
                            1..512 => match serde_json::from_str::<ClientSubscriptions>(&text) {
                                Ok(subs) => {
                                    clients.lock().await.get_mut(&addr).unwrap().subscriptions =
                                        subs;
                                    continue;
                                }
                                Err(e) => {
                                    log::warn!("Could not parse client subscriptions from message: '{truncated_text}'; Disconnecting '{addr}' due to error: {e}");
                                }
                            },
                            512.. => {
                                log::warn!(
                                    "Received large message '{truncated_text}..' from client {addr}. Disconnecting."
                                );
                            }
                        };

                        // if we didn't continue above, we should close the connection to
                        if let Some(client) = clients.lock().await.get_mut(&addr) {
                            client.outgoing.close().await?;
                        }
                        clients.lock().await.remove(&addr);
                    }
                    _ => (),
                }
            }
            Err(_) => {
                log::info!("Client '{}' disconnected", addr);
                // Remove the client from the shared list if the connection is closed
                clients.lock().await.remove(&addr);
                break;
            }
        }
    }
    Ok(())
}

async fn broadcast_to_clients(event: &PeerObserverEvent, clients: &Clients) {
    let message = match serde_json::to_string::<PeerObserverEvent>(event) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Could not serialize the message to JSON: {}", e);
            return;
        }
    };

    let mut clients = clients.lock().await;
    for (addr, client) in clients.iter_mut() {
        let is_subscribed = match event {
            PeerObserverEvent::EbpfExtractor(ebpf) => match &ebpf.ebpf_event {
                Some(ebpf::EbpfEvent::Message(_)) => client.subscriptions.ebpf.messages,
                Some(ebpf::EbpfEvent::Connection(_)) => client.subscriptions.ebpf.connections,
                Some(ebpf::EbpfEvent::Mempool(_)) => client.subscriptions.ebpf.mempool,
                Some(ebpf::EbpfEvent::Validation(_)) => client.subscriptions.ebpf.validation,
                None => false,
            },
            PeerObserverEvent::RpcExtractor(_) => client.subscriptions.rpc,
            PeerObserverEvent::P2pExtractor(_) => client.subscriptions.p2p,
            PeerObserverEvent::LogExtractor(_) => client.subscriptions.log,
            PeerObserverEvent::IpcExtractor(_) => client.subscriptions.ipc,
        };

        if !is_subscribed {
            continue;
        }

        if let Err(e) = client
            .outgoing
            .send(TungsteniteMessage::text(&message))
            .await
        {
            log::warn!("Failed to send message to client '{}': {}", addr, e);
        }
    }
}
