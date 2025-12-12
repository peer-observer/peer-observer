use shared::{
    async_nats,
    bitcoin::{
        Network as BitcoinNetwork,
        consensus::{Decodable, Encodable},
        io::Cursor as BitcoinCursor,
        p2p::{
            ServiceFlags, address,
            message::{self, NetworkMessage, RawNetworkMessage},
            message_network,
        },
    },
    clap::{self, Parser, ValueEnum},
    log,
    nats_subjects::Subject,
    prost::Message,
    protobuf::{
        bitcoin_primitives,
        event::{Event, event::PeerObserverEvent},
        p2p_extractor,
    },
    rand::{self, Rng},
    tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream, tcp::WriteHalf},
        sync::watch,
        time::{self, Duration},
    },
    util,
};

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

mod error;

use error::{BitcoinMsgDecodeError, RuntimeError};

const USER_AGENT: &str = "/p2p-extractor:0.1/";

/// Enum of all possible networks. These determine the network magic.
#[derive(Debug, Clone, ValueEnum)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Network::Mainnet => "mainnet",
            Network::Testnet3 => "testnet3",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
        };
        write!(f, "{}", s)
    }
}

impl From<Network> for BitcoinNetwork {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => BitcoinNetwork::Bitcoin,
            Network::Testnet3 => BitcoinNetwork::Testnet,
            Network::Testnet4 => BitcoinNetwork::Testnet4,
            Network::Regtest => BitcoinNetwork::Regtest,
            Network::Signet => BitcoinNetwork::Signet,
        }
    }
}

/// The peer-observer p2p-extractor listens for a connection from a Bitcoin
/// node and once connected, extracts events from exchanged P2P messages. It
/// publishes the events into a NATS pub-sub queue.
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Address of the NATS server where the extractor will publish messages to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    pub nats_address: String,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html.
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,

    /// Address of the P2P interface the P2P extractor will listen on.
    /// On the Bitcoin node side, the connection needs to be established
    /// with -addnode=<p2p_address>.
    #[arg(long, default_value = "127.0.0.1:9333")]
    pub p2p_address: String,

    /// Network (P2P) the Bitcoin node is on. This determines the network magic.
    /// The network magic of the p2p-extractor and the Bitcoin node must match.
    #[arg(long, default_value_t = Network::Mainnet)]
    pub p2p_network: Network,

    /// The p2p_extractor frequently pings the connected node to measure ping and backlog timings.
    /// This allows to configure the ping interval (in seconds).
    #[arg(long, default_value_t = 10)]
    pub ping_interval: u64,

    /// The p2p_extractor frequently pings the connected node to measure ping and backlog timings.
    /// This allows disabling the ping measurements.
    #[arg(long, default_value_t = false)]
    pub disable_ping: bool,

    /// The p2p_extractor publishes events for addresses the node annouces to us.
    /// This allows disabling the address annoucement events.
    #[arg(long, default_value_t = false)]
    pub disable_addrv2: bool,

    /// The p2p_extractor publishes events for invs the node annouces to us.
    /// This allows disabling the inv annoucement events.
    #[arg(long, default_value_t = false)]
    pub disable_invs: bool,

    /// The p2p_extractor publishes events for feefilters the node annouces to us.
    /// This allows disabling the feefilter annoucement events.
    #[arg(long, default_value_t = false)]
    pub disable_feefilter: bool,
}

impl Args {
    pub fn new(
        nats_address: String,
        log_level: log::Level,
        p2p_address: String,
        p2p_network: Network,
        ping_interval: u64,
        disable_ping: bool,
        disable_addrv2: bool,
        disable_invs: bool,
        disable_feefilter: bool,
    ) -> Args {
        Self {
            nats_address,
            log_level,
            p2p_address,
            p2p_network,
            ping_interval,
            disable_ping,
            disable_addrv2,
            disable_invs,
            disable_feefilter,
            // when adding more disable_* args, make sure to update the disable_all below
        }
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    log::info!("Using network magic for: {}", args.p2p_network);
    let network: BitcoinNetwork = args.p2p_network.clone().into();
    log::info!("Ping measurements enabled: {}", !args.disable_ping);
    if !args.disable_ping {
        log::info!("Ping measurements interval: {}s", args.ping_interval);
    }
    log::info!("Addrv2 events enabled: {}", !args.disable_addrv2);
    log::info!("Invs events enabled: {}", !args.disable_invs);
    // check if at least one P2P measurement is enabled
    let disable_all = args.disable_ping && args.disable_addrv2 && args.disable_invs;
    if disable_all {
        log::warn!("No P2P measurement enabled!");
    }

    log::debug!("Connecting to NATS server at {}..", args.nats_address);
    let nats_client = async_nats::connect(&args.nats_address).await?;
    log::info!("Connected to NATS server at {}", &args.nats_address);

    log::debug!("Starting TCP listener on {}..", args.p2p_address);
    let listener = TcpListener::bind(args.p2p_address.clone()).await?;
    let local_addr = listener.local_addr()?;
    log::info!("P2P-extractor listening on {}", local_addr);

    loop {
        shared::tokio::select! {
            res = listener.accept() => {
                if let Ok(connection) = res {
                    let (socket, addr) = connection;
                    log::info!("accepted a new connection from: {}", addr);
                    let nats_client_clone = nats_client.clone();
                    shared::tokio::task::spawn(handle_connection(socket, network, args.clone(), nats_client_clone));

                } else {
                    log::warn!("Could not accept connection on socket: {:?}", res);
                }
            },
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("p2p-extractor received shutdown signal.");
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

async fn handle_connection(
    mut stream: TcpStream,
    network: BitcoinNetwork,
    args: Args,
    nats_client: async_nats::Client,
) {
    let addr: &str = match stream.peer_addr() {
        Ok(addr) => &addr.to_string(),
        Err(e) => {
            log::error!("Could not get the address of the peer: {}", e);
            return;
        }
    };
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);
    let mut ping_interval = time::interval(Duration::from_secs(args.ping_interval));
    let mut verack_done = false;

    async fn send_message(
        msg: message::NetworkMessage,
        network: BitcoinNetwork,
        write_half: &mut WriteHalf<'_>,
        addr: &str,
    ) {
        let reply: RawNetworkMessage = build_raw_network_message(msg.clone(), network);
        let mut out_bytes = Vec::new();
        reply.consensus_encode(&mut out_bytes).unwrap();
        match write_half.write_all(&out_bytes).await {
            Ok(_) => log::trace!(target: addr, "sent message: {:?}", msg),
            Err(e) => log::warn!(target: addr, "failed to sent message: {:?}", e),
        };
    }

    loop {
        shared::tokio::select! {
            _ = ping_interval.tick() => {
                if !args.disable_ping && verack_done {
                    let timestamp: u64 = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time error")
                        .as_nanos() as u64; // Treating nanoseconds as u64 will be fine for the next 500 years or so.
                    send_message(NetworkMessage::Ping(timestamp), network, &mut write_half, addr).await;
                }
            }
            result = read_and_decode_message(&mut reader, network, addr) => {
                match result {
                    Ok(raw_msg) => {
                        log::trace!(target: addr, "received message: {:?}", raw_msg.payload());
                        match raw_msg.payload() {
                            NetworkMessage::Version(_) => {
                                send_message(build_version_message(), network, &mut write_half, addr).await;
                                // indicate support for addrv2 during version handshake
                                send_message(NetworkMessage::SendAddrV2, network, &mut write_half, addr).await;
                                // indicate that we want to receive wtxids in invs (see BIP339)
                                send_message(NetworkMessage::WtxidRelay, network, &mut write_half, addr).await;
                            }
                            NetworkMessage::Verack => {
                                send_message(NetworkMessage::Verack, network, &mut write_half, addr).await;
                                verack_done = true;
                            }
                            NetworkMessage::Ping(nonce) => {
                                send_message(NetworkMessage::Pong(*nonce), network, &mut write_half, addr).await;
                            }
                            NetworkMessage::Pong(nonce) => {
                                // The "nonce" we initial sent is a timestamp.
                                let now: u64 = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time error")
                                    .as_nanos() as u64;
                                let duration = now - nonce;
                                log::debug!(target: addr, "processing the ping message took: {}ns", now - nonce);
                                publish_ping_measurement_event(duration, &nats_client).await;
                            }
                            NetworkMessage::AddrV2(addrs) => {
                                log::debug!(target: addr, "received addrv2: {:?}", addrs);
                                let addresses: Vec<bitcoin_primitives::Address>  = addrs
                                    .iter()
                                    .map(|addr_entry| addr_entry.clone().into())
                                    .collect();
                                publish_addr_announcement_event(addresses, &nats_client).await;
                            }
                            NetworkMessage::Inv(inventory) => {
                                log::debug!(target: addr, "received inv: {:?}", inventory);
                                if !args.disable_invs {
                                    let items: Vec<bitcoin_primitives::InventoryItem> = inventory
                                        .iter()
                                        .map(|i| i.clone().into())
                                        .collect();
                                    publish_inventory_announcement_event(items, &nats_client).await;
                                }
                            }
                            NetworkMessage::FeeFilter(feefilter) => {
                                log::debug!(target: addr, "received feefilter: {}", feefilter);
                                if !args.disable_feefilter {
                                    publish_feefilter_announcement_event(*feefilter, &nats_client).await;
                                }
                            }
                            NetworkMessage::Alert(_) => {
                                // ignore these for now..
                                // and treat all other messages as unhandled
                            }
                            _ => {
                                log::debug!(target: addr, "unhandled message type: {}", raw_msg.command());
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(target: addr, "error decoding message: {}", e);
                        break;
                    }
                }
            }
        }
    }
    log::info!("closing connection: '{}'", addr);
    let _ = stream.shutdown();
}

async fn publish_addr_announcement_event(
    addresses: Vec<bitcoin_primitives::Address>,
    nats_client: &async_nats::Client,
) {
    let proto_result = Event::new(PeerObserverEvent::P2pExtractor(p2p_extractor::P2p {
        p2p_event: Some(p2p_extractor::p2p::P2pEvent::AddressAnnouncement(
            p2p_extractor::AddressAnnouncement { addresses },
        )),
    }));

    match proto_result {
        Ok(proto) => {
            if let Err(e) = nats_client
                .publish(
                    Subject::P2PExtractor.to_string(),
                    proto.encode_to_vec().into(),
                )
                .await
            {
                log::error!("could not publish addr announcement into NATS: {}", e);
            } else {
                log::trace!("published addr announcement into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!("could not create addr announcement protobuf: {}", e);
        }
    }
}

async fn publish_inventory_announcement_event(
    inventory: Vec<bitcoin_primitives::InventoryItem>,
    nats_client: &async_nats::Client,
) {
    let proto_result = Event::new(PeerObserverEvent::P2pExtractor(p2p_extractor::P2p {
        p2p_event: Some(p2p_extractor::p2p::P2pEvent::InventoryAnnouncement(
            p2p_extractor::InventoryAnnouncement { inventory },
        )),
    }));

    match proto_result {
        Ok(proto) => {
            if let Err(e) = nats_client
                .publish(
                    Subject::P2PExtractor.to_string(),
                    proto.encode_to_vec().into(),
                )
                .await
            {
                log::error!("could not publish inventory announcement into NATS: {}", e);
            } else {
                log::trace!("published inventory announcement into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!("could not create inventory announcement protobuf: {}", e);
        }
    }
}

async fn publish_feefilter_announcement_event(feefilter: i64, nats_client: &async_nats::Client) {
    let proto_result = Event::new(PeerObserverEvent::P2pExtractor(p2p_extractor::P2p {
        p2p_event: Some(p2p_extractor::p2p::P2pEvent::FeefilterAnnouncement(
            feefilter,
        )),
    }));

    match proto_result {
        Ok(proto) => {
            if let Err(e) = nats_client
                .publish(
                    Subject::P2PExtractor.to_string(),
                    proto.encode_to_vec().into(),
                )
                .await
            {
                log::error!("could not publish feefilter announcement into NATS: {}", e);
            } else {
                log::trace!("published feefilter announcement into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!("could not create feefilter announcement protobuf: {}", e);
        }
    }
}

async fn publish_ping_measurement_event(duration: u64, nats_client: &async_nats::Client) {
    let proto_result = Event::new(PeerObserverEvent::P2pExtractor(p2p_extractor::P2p {
        p2p_event: Some(p2p_extractor::p2p::P2pEvent::PingDuration(
            p2p_extractor::PingDuration { duration },
        )),
    }));

    match proto_result {
        Ok(proto) => {
            if let Err(e) = nats_client
                .publish(
                    Subject::P2PExtractor.to_string(),
                    proto.encode_to_vec().into(),
                )
                .await
            {
                log::error!("could not publish Ping measurement into NATS: {}", e);
            } else {
                log::trace!("published Ping measurement into NATS: {:?}", proto);
            }
        }
        Err(e) => {
            log::error!("could not create Ping measurement protobuf: {}", e);
        }
    }
}

async fn read_and_decode_message<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    network: BitcoinNetwork,
    addr: &str,
) -> Result<RawNetworkMessage, BitcoinMsgDecodeError> {
    let mut header = [0u8; 24];
    if let Err(e) = reader.read_exact(&mut header).await {
        log::debug!(
            "reading the P2P message header from '{}' failed: {}",
            addr,
            e
        );
        return Err(BitcoinMsgDecodeError::HeaderReadError(e));
    }

    // We only accept v1 connections. To filter out V2 connections, error on everything
    // that doesn't match the network magic.
    let header_magic: [u8; 4] = header[0..4].try_into().expect("slice should have length 4");
    if header_magic != network.magic().to_bytes() {
        log::debug!(target: addr,
            "mismatch in the P2P message magic: this could mean the node is on a different network or it's attempting a P2Pv2 connection..",
        );
        return Err(BitcoinMsgDecodeError::MagicError(
            network.magic().to_bytes(),
            header_magic,
        ));
    }

    let payload_length = u32::from_le_bytes(header[16..20].try_into()?);
    let mut payload = vec![0u8; payload_length as usize];
    if let Err(e) = reader.read_exact(&mut payload).await {
        log::debug!(target: addr,
            "reading the P2P message payload failed: {}",
            e
        );
        return Err(BitcoinMsgDecodeError::PayloadReadError(e));
    }

    let mut full_msg_bytes = Vec::with_capacity(24 + payload.len());
    full_msg_bytes.extend_from_slice(&header);
    full_msg_bytes.extend_from_slice(&payload);

    let mut cursor = BitcoinCursor::new(full_msg_bytes);
    let msg = RawNetworkMessage::consensus_decode(&mut cursor)?;

    Ok(msg)
}

fn build_raw_network_message(
    payload: message::NetworkMessage,
    network: BitcoinNetwork,
) -> message::RawNetworkMessage {
    message::RawNetworkMessage::new(network.magic(), payload)
}

fn build_version_message() -> message::NetworkMessage {
    message::NetworkMessage::Version(message_network::VersionMessage {
        // use version 70016 to indicate we want wtxids for transaction invs
        // see https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki
        version: 70016,
        services: ServiceFlags::NONE,
        timestamp: util::current_timestamp() as i64,
        receiver: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            ServiceFlags::NONE,
        ),
        sender: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            ServiceFlags::NONE,
        ),
        nonce: rand::rng().random(),
        user_agent: String::from(USER_AGENT),
        start_height: 0,
        relay: true, // indicates to the node that we want to receive transactions
    })
}
