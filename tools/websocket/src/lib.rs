#![cfg_attr(feature = "strict", deny(warnings))]

use shared::clap::Parser;
use shared::futures::{stream::SplitSink, SinkExt, StreamExt};
use shared::log;
use shared::prost::Message;
use shared::protobuf::event::{self, event::PeerObserverEvent};
use shared::{
    async_nats, clap,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::{watch, Mutex},
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
    /// The NATS server address the tool should connect and subscribe to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    pub nats_address: String,

    /// The websocket address the tool listens on.
    #[arg(short, long, default_value = "127.0.0.1:47482")]
    pub websocket_address: String,

    /// The log level the took should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,
}

impl Args {
    pub fn new(nats_address: String, websocket_address: String, log_level: log::Level) -> Self {
        Self {
            nats_address,
            websocket_address,
            log_level,
        }
    }
}

type Clients =
    Arc<Mutex<HashMap<SocketAddr, SplitSink<WebSocketStream<TcpStream>, TungsteniteMessage>>>>;

pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), error::RuntimeError> {
    log::debug!("Connecting to NATS-server at {}", args.nats_address);
    let nc = async_nats::connect(args.nats_address.clone()).await?;
    log::info!("Connected to NATS-server at {}", args.nats_address);
    let mut sub = nc.subscribe("*").await?;

    let clients = Arc::new(Mutex::new(HashMap::new()));

    // Spawn a thread to handle NATS messages and broadcast to WebSocket clients
    {
        let clients = Arc::clone(&clients);
        tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                match event::Event::decode(msg.payload) {
                    Ok(event) => {
                        if let Some(event) = event.peer_observer_event {
                            match serde_json::to_string::<PeerObserverEvent>(&event.clone()) {
                                Ok(msg) => {
                                    broadcast_to_clients(&msg, &clients).await;
                                }
                                Err(e) => {
                                    log::error!("Could not serialize the message to JSON: {}", e)
                                }
                            }
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
    clients.lock().await.insert(addr, outgoing);

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
                    _ => (), // We ignore all other messages a client sends us.
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

async fn broadcast_to_clients(message: &str, clients: &Clients) {
    let mut clients = clients.lock().await;

    for (addr, outgoing) in clients.iter_mut() {
        if let Err(e) = outgoing.send(TungsteniteMessage::text(message)).await {
            log::warn!("Failed to send message to client '{}': {}", addr, e);
        }
    }
}
