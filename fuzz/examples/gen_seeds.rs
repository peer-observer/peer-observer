//! Regenerates the seed corpora in `seeds/`. Run from the `fuzz/` directory:
//!
//! ```text
//! cargo run --example gen_seeds
//! ```
//!
//! Seeds are small, valid inputs that let the fuzzer start from the
//! interesting part of each input format instead of having to discover the
//! framing and magic values on its own.

use peer_observer_fuzz::layout::{p2p_message_entry, P2P_METADATA_SIZE};
use peer_observer_fuzz::{dummy_metadata, wrap_ebpf_event, wrap_event};
use shared::bitcoin::consensus::{deserialize, serialize};
use shared::bitcoin::hashes::Hash;
use shared::bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use shared::bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use shared::bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use shared::bitcoin::p2p::message_compact_blocks::SendCmpct;
use shared::bitcoin::p2p::message_network::VersionMessage;
use shared::bitcoin::p2p::ServiceFlags;
use shared::bitcoin::{BlockHash, Network, Transaction, Txid};
use shared::log_matchers::parse_log_event;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::ebpf_extractor::ctypes::{ClosedConnection, InboundConnection, MempoolAdded};
use shared::protobuf::ebpf_extractor::message::{message_event, MessageEvent};
use shared::protobuf::ebpf_extractor::{connection, ebpf};
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use std::fs;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

const LOG_LINES: &[&str] = &[
    "2025-10-02T02:31:14Z Verification progress: 50%",
    "2025-10-02T02:31:21Z [net] Flushed 0 addresses to peers.dat  2ms",
    "2025-09-27T01:52:01Z [validation] Enqueuing BlockConnected: block hash=41109f31c8ca4d8683ab5571ba462292ddb8486dee6ecd2e62901accc7952f0b block height=437",
    "2026-04-06T15:02:09.010720Z Saw new header hash=00000000000000000001405ace6e6e4abd39fd1e13d1b3434468ba99986b6ad5 height=943929 peer=498",
    "2026-04-06T15:02:09.123456Z [msghand] [cmpctblock] Successfully reconstructed block 00000000000000000001405ace6e6e4abd39fd1e13d1b3434468ba99986b6ad5 with 1 txn prefilled, 3000 txn from mempool (incl at least 2 from extra pool) and 0 txn (0 bytes) requested",
    "2026-04-06T15:02:09Z [validation] BlockChecked: block hash=00000000000000000001405ace6e6e4abd39fd1e13d1b3434468ba99986b6ad5 state=Valid",
    "2026-04-06T15:02:09Z [error] Something went wrong",
];

/// A one-input one-output transaction (mainnet, no witness).
const TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(dir).expect("create seed dir");
    fs::write(dir.join(name), bytes).expect("write seed");
}

fn network_messages() -> Vec<NetworkMessage> {
    let tx: Transaction = deserialize(&hex_decode(TX_HEX)).expect("valid tx");
    let block_hash = BlockHash::from_byte_array([0x42; 32]);
    let txid = Txid::from_byte_array([0x24; 32]);
    let socket = SocketAddr::new(Ipv4Addr::new(203, 0, 113, 7).into(), 8333);

    vec![
        NetworkMessage::Ping(0x1122334455667788),
        NetworkMessage::Pong(0x1122334455667788),
        NetworkMessage::Verack,
        NetworkMessage::WtxidRelay,
        NetworkMessage::SendAddrV2,
        NetworkMessage::SendHeaders,
        NetworkMessage::GetAddr,
        NetworkMessage::FeeFilter(1000),
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
        NetworkMessage::Version(VersionMessage::new(
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            1_700_000_000,
            Address::new(&socket, ServiceFlags::NONE),
            Address::new(&socket, ServiceFlags::NETWORK),
            0xdeadbeef,
            "/Satoshi:28.0.0/".to_string(),
            900_000,
        )),
        NetworkMessage::Inv(vec![
            Inventory::WTx(shared::bitcoin::Wtxid::from_byte_array([0x11; 32])),
            Inventory::Block(block_hash),
            Inventory::Transaction(txid),
        ]),
        NetworkMessage::GetData(vec![Inventory::WitnessBlock(block_hash)]),
        NetworkMessage::NotFound(vec![Inventory::Transaction(txid)]),
        NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![block_hash], block_hash)),
        NetworkMessage::Addr(vec![(
            1_700_000_000,
            Address::new(&socket, ServiceFlags::NETWORK),
        )]),
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time: 1_700_000_000,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::TorV3([0x33; 32]),
            port: 8333,
        }]),
        NetworkMessage::Tx(tx),
        NetworkMessage::Unknown {
            command: "foobar".parse().expect("valid command"),
            payload: vec![1, 2, 3],
        },
    ]
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn main() {
    let seeds = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    let messages = network_messages();
    let mut events: Vec<Event> = Vec::new();

    // p2p_read_message: full raw messages as they arrive on the socket.
    // ebpf_p2p_message: ring buffer entries (metadata struct + payload).
    for msg in &messages {
        let raw = serialize(&RawNetworkMessage::new(
            Network::Bitcoin.magic(),
            msg.clone(),
        ));
        let payload = &raw[24..];
        write_seed(&seeds.join("p2p_read_message"), msg.cmd(), &raw);

        let entry = p2p_message_entry(
            9674439,
            "209.222.252.40:64809",
            "inbound",
            msg.cmd(),
            true,
            payload,
        );
        write_seed(&seeds.join("ebpf_p2p_message"), msg.cmd(), &entry);

        events.push(wrap_ebpf_event(ebpf::EbpfEvent::Message(MessageEvent {
            meta: dummy_metadata(msg.cmd(), payload.len() as u64),
            msg: Some(message_event::Msg::from(msg)),
        })));
    }
    // An empty addrv2 and a nonce-less ping are handled as special cases.
    for cmd in ["addrv2", "ping"] {
        let entry = p2p_message_entry(1, "127.0.0.1:8333", "outbound-full-relay", cmd, false, &[]);
        write_seed(
            &seeds.join("ebpf_p2p_message"),
            &format!("empty-{cmd}"),
            &entry,
        );
    }
    assert_eq!(
        P2P_METADATA_SIZE, 120,
        "metadata layout changed, update the tests"
    );

    // ebpf_ringbuffer: a kind byte followed by a (mostly zero) struct.
    let mut closed = vec![0u8; 1 + size_of::<ClosedConnection>()];
    closed[0] = 0;
    closed[1..9].copy_from_slice(&7u64.to_ne_bytes());
    closed[9..9 + 14].copy_from_slice(b"127.0.0.1:8333");
    write_seed(&seeds.join("ebpf_ringbuffer"), "closed", &closed);
    let mut inbound = vec![0u8; 1 + size_of::<InboundConnection>()];
    inbound[0] = 2;
    inbound[9..9 + 14].copy_from_slice(b"127.0.0.1:8333");
    inbound[9 + 68..9 + 68 + 7].copy_from_slice(b"inbound");
    write_seed(&seeds.join("ebpf_ringbuffer"), "inbound", &inbound);
    let mut added = vec![0u8; 1 + size_of::<MempoolAdded>()];
    added[0] = 5;
    added[1..33].copy_from_slice(&[0x24; 32]);
    write_seed(&seeds.join("ebpf_ringbuffer"), "mempool-added", &added);
    let mut connected =
        vec![
            0u8;
            1 + size_of::<shared::protobuf::ebpf_extractor::ctypes::ValidationBlockConnected>()
        ];
    connected[0] = 9;
    connected[1..33].copy_from_slice(&[0x42; 32]);
    write_seed(
        &seeds.join("ebpf_ringbuffer"),
        "block-connected",
        &connected,
    );

    // log_line
    for (i, line) in LOG_LINES.iter().enumerate() {
        write_seed(
            &seeds.join("log_line"),
            &format!("line-{i}"),
            line.as_bytes(),
        );
        events.push(wrap_event(PeerObserverEvent::LogExtractor(
            parse_log_event(line),
        )));
    }

    // A connection event, for variety in the event corpora.
    events.push(wrap_ebpf_event(ebpf::EbpfEvent::Connection(
        connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::Inbound(
                connection::InboundConnection {
                    conn: connection::Connection {
                        peer_id: 7,
                        addr: "203.0.113.7:8333".to_string(),
                        conn_type: 1,
                        network: 1,
                    },
                    existing_connections: 12,
                },
            )),
        },
    )));

    // event_decode: one event per file. archive_reader: all events in one archive.
    let mut events_bytes = Vec::new();
    for (i, event) in events.iter().enumerate() {
        write_seed(
            &seeds.join("event_decode"),
            &format!("event-{i}"),
            &event.encode_to_vec(),
        );
        events_bytes.extend_from_slice(&event.encode_length_delimited_to_vec());
    }
    // metrics_events, alerts_events: a sequence of length-delimited events, as
    // received over NATS.
    write_seed(&seeds.join("metrics_events"), "all-events", &events_bytes);
    write_seed(&seeds.join("alerts_events"), "all-events", &events_bytes);
    // archive_reader: the same sequence behind an archive header.
    let mut archive = ArchiveHeader {
        created: 1_700_000_000,
        low_data: Some(false),
    }
    .to_bytes();
    archive.extend_from_slice(&events_bytes);
    write_seed(&seeds.join("archive_reader"), "all-events", &archive);
    let header_only = ArchiveHeader {
        created: 1_700_000_000,
        low_data: None,
    }
    .to_bytes();
    write_seed(&seeds.join("archive_reader"), "header-only", &header_only);

    println!("wrote seeds to {}", seeds.display());
}
