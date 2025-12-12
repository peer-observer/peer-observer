#![cfg_attr(feature = "strict", deny(warnings))]

use error::RuntimeError;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Map, MapCore, Object, ProgramMut, RingBufferBuilder};
use shared::clap::Parser;
use shared::log::{self, error};
use shared::nats_subjects::Subject;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::ctypes::{
    AddrmanInsertNew, AddrmanInsertTried, ClosedConnection, InboundConnection, MempoolAdded,
    MempoolRejected, MempoolRemoved, MempoolReplaced, MisbehavingConnection, OutboundConnection,
    P2PMessage, ValidationBlockConnected,
};
use shared::protobuf::ebpf_extractor::{
    addrman, connection, ebpf, mempool, message, validation, Ebpf,
};
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::simple_logger;
use shared::{async_nats, clap, tokio};
use std::fs::File;
use std::io::{BufReader, Read};
use std::mem::MaybeUninit;
use std::time::Duration;
use std::time::SystemTime;

mod error;
#[path = "tracing.gen.rs"]
mod tracing;

const RINGBUFF_CALLBACK_OK: i32 = 0;
const RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR: i32 = -5;
const RINGBUFF_CALLBACK_UNABLE_TO_PARSE_P2P_MSG: i32 = -20;

const NO_EVENTS_ERROR_DURATION: Duration = Duration::from_secs(60 * 3);
const NO_EVENTS_WARN_DURATION: Duration = Duration::from_secs(60 * 1);

struct Tracepoint<'a> {
    pub context: &'a str,
    pub name: &'a str,
    pub function: &'a str,
}

// Update the ebpf-extractor docs in the README.md when editing these.
const TRACEPOINTS_NET_MESSAGE: [Tracepoint; 2] = [
    Tracepoint {
        context: "net",
        name: "inbound_message",
        function: "handle_net_msg_inbound",
    },
    Tracepoint {
        context: "net",
        name: "outbound_message",
        function: "handle_net_msg_outbound",
    },
];

// Update the ebpf-extractor docs in the README.md when editing these.
const TRACEPOINTS_NET_CONN: [Tracepoint; 5] = [
    Tracepoint {
        context: "net",
        name: "inbound_connection",
        function: "handle_net_conn_inbound",
    },
    Tracepoint {
        context: "net",
        name: "outbound_connection",
        function: "handle_net_conn_outbound",
    },
    Tracepoint {
        context: "net",
        name: "closed_connection",
        function: "handle_net_conn_closed",
    },
    Tracepoint {
        context: "net",
        name: "evicted_inbound_connection",
        function: "handle_net_conn_inbound_evicted",
    },
    Tracepoint {
        context: "net",
        name: "misbehaving_connection",
        function: "handle_net_conn_misbehaving",
    },
];

// Update the ebpf-extractor docs in the README.md when editing these.
const TRACEPOINTS_MEMPOOL: [Tracepoint; 4] = [
    Tracepoint {
        context: "mempool",
        name: "added",
        function: "handle_mempool_added",
    },
    Tracepoint {
        context: "mempool",
        name: "removed",
        function: "handle_mempool_removed",
    },
    Tracepoint {
        context: "mempool",
        name: "replaced",
        function: "handle_mempool_replaced",
    },
    Tracepoint {
        context: "mempool",
        name: "rejected",
        function: "handle_mempool_rejected",
    },
];

// Update the ebpf-extractor docs in the README.md when editing these.
const TRACEPOINTS_ADDRMAN: [Tracepoint; 2] = [
    Tracepoint {
        context: "addrman",
        name: "attempt_add",
        function: "handle_addrman_new",
    },
    Tracepoint {
        context: "addrman",
        name: "move_to_good",
        function: "handle_addrman_tried",
    },
];

// Update the ebpf-extractor docs in the README.md when editing these.
const TRACEPOINTS_VALIDATION: [Tracepoint; 1] = [Tracepoint {
    context: "validation",
    name: "block_connected",
    function: "handle_validation_block_connected",
}];

/// The peer-observer extractor hooks into a Bitcoin Core binary with
/// tracepoints and publishes events into a NATS pub-sub queue.
#[derive(Parser, Debug)]
#[clap(group(
    clap::ArgGroup::new("pid")
        .required(true)
        .multiple(false)
        .args(&["bitcoind_pid", "bitcoind_pid_file"])
))]
#[command(version, about, long_about = None)]
struct Args {
    /// Address of the NATS server where the extractor will publish messages to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    nats_address: String,

    /// Path to the Bitcoin Core (bitcoind) binary that should be hooked into.
    #[arg(short, long)]
    bitcoind_path: String,

    /// PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into.
    /// Either this or --bitcoind-pid-file must be set.
    #[arg(long)]
    bitcoind_pid: Option<i32>,

    /// File containing the PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into.
    /// Either this or --bitcoind-pid must be set.
    #[arg(long)]
    bitcoind_pid_file: Option<String>,

    // Default tracepoints
    /// Controls if the p2p message tracepoints should be hooked into.
    #[arg(long)]
    no_p2pmsg_tracepoints: bool,
    /// Controls if the connection tracepoints should be hooked into.
    #[arg(long)]
    no_connection_tracepoints: bool,
    /// Controls if the mempool tracepoints should be hooked into.
    #[arg(long)]
    no_mempool_tracepoints: bool,
    /// Controls if the validation tracepoints should be hooked into.
    #[arg(long)]
    no_validation_tracepoints: bool,

    // Custom tracepoints
    /// Controls if the addrman tracepoints should be hooked into.
    /// These may not have been PRed to Bitcoin Core yet.
    #[arg(long)]
    addrman_tracepoints: bool,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html
    #[arg(short, long, default_value_t = log::Level::Debug)]
    log_level: log::Level,

    /// If used, libbpf will print debug information about the BPF maps,
    /// programs, and tracepoints during extractor startup. This can be
    /// useful during debugging.
    #[arg(long, default_value_t = false)]
    libbpf_debug: bool,

    /// The ebpf-extractor will exit if it doesn't detect activity in the ebpf
    /// buffers for 180 seconds. This flag disables this and only emits warnings
    /// about inactivity. This can be useful during debugging.
    #[arg(short = 'i', long)]
    no_idle_exit: bool,
}

/// Find the BPF program with the given name
pub fn find_prog_mut<'obj>(
    object: &'obj Object,
    name: &str,
) -> Result<ProgramMut<'obj>, RuntimeError> {
    match object.progs_mut().find(|prog| prog.name() == name) {
        Some(prog) => Ok(prog),
        None => Err(RuntimeError::NoSuchBPFProg(name.to_string())),
    }
}

/// Find the BPF map with the given name
pub fn find_map<'obj>(object: &'obj Object, name: &str) -> Result<Map<'obj>, RuntimeError> {
    match object.maps().find(|map| map.name() == name) {
        Some(map) => Ok(map),
        None => Err(RuntimeError::NoSuchBPFMap(name.to_string())),
    }
}

fn bitcoind_pid(args: &Args) -> Result<i32, RuntimeError> {
    // The clap arg group "pid" takes care that one of bitcoind_pid or
    // bitcoind_pid_file is set
    if let Some(pid) = args.bitcoind_pid {
        log::info!(
            "Using bitcoind PID={} specified via command line option",
            pid
        );
        return Ok(pid);
    }
    // so if we haven't returned here, we can be sure that the pid
    // file is set.
    let path = args
        .bitcoind_pid_file
        .clone()
        .expect("pid file path should be set");
    log::info!(
        "Reading bitcoind PID file '{}' specified via command line option",
        path
    );

    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    reader.read_to_string(&mut content)?;
    let pid: i32 = content.trim().parse()?;
    log::info!("Using bitcoind PID={} read from {}", pid, path);
    Ok(pid)
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        log::error!("Fatal error during extractor runtime: {}", e);
    }
}

async fn run() -> Result<(), RuntimeError> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level)?;

    let pid = bitcoind_pid(&args)?;

    let mut skel_builder = tracing::TracingSkelBuilder::default();
    skel_builder.obj_builder.debug(args.libbpf_debug);

    let mut uninit = MaybeUninit::uninit();
    log::info!("Opening BPF skeleton with debug={}..", args.libbpf_debug);
    let open_skel: tracing::OpenTracingSkel = skel_builder.open(&mut uninit)?;
    log::info!("Loading BPF functions and maps into kernel..");
    let skel: tracing::TracingSkel = open_skel.load()?;
    let obj = skel.object();

    log::debug!("Connecting to NATS server at {}..", args.nats_address);
    let nc = async_nats::connect(&args.nats_address).await?;
    log::info!("Connected to NATS server at {}", &args.nats_address);

    // Update the ebpf-extractor docs in the README.md when editing the active_tracepoints.
    let mut active_tracepoints = vec![];
    let mut ringbuff_builder = RingBufferBuilder::new();

    // P2P net msgs tracepoints
    let map_net_msg_small = find_map(&obj, "net_msg_small")?;
    let map_net_msg_medium = find_map(&obj, "net_msg_medium")?;
    let map_net_msg_large = find_map(&obj, "net_msg_large")?;
    let map_net_msg_huge = find_map(&obj, "net_msg_huge")?;
    if !args.no_p2pmsg_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_NET_MESSAGE);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        ringbuff_builder
            .add(&map_net_msg_small,    |data| { handle_net_message(data, &nc) })?
            .add(&map_net_msg_medium,   |data| { handle_net_message(data, &nc) })?
            .add(&map_net_msg_large,    |data| { handle_net_message(data, &nc) })?
            .add(&map_net_msg_huge,     |data| { handle_net_message(data, &nc) })?;
    }

    // P2P connection tracepoints
    let map_net_conn_inbound = find_map(&obj, "net_conn_inbound")?;
    let map_net_conn_outbound = find_map(&obj, "net_conn_outbound")?;
    let map_net_conn_closed = find_map(&obj, "net_conn_closed")?;
    let map_net_conn_inbound_evicted = find_map(&obj, "net_conn_inbound_evicted")?;
    let map_net_conn_misbehaving = find_map(&obj, "net_conn_misbehaving")?;
    if !args.no_connection_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_NET_CONN);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        ringbuff_builder
            .add(&map_net_conn_inbound,         |data| { handle_net_conn_inbound(data, &nc) })?
            .add(&map_net_conn_outbound,        |data| { handle_net_conn_outbound(data, &nc) })?
            .add(&map_net_conn_closed,          |data| { handle_net_conn_closed(data, &nc) })?
            .add(&map_net_conn_inbound_evicted, |data| { handle_net_conn_inbound_evicted(data, &nc) })?
            .add(&map_net_conn_misbehaving,     |data| { handle_net_conn_misbehaving(data, &nc) })?;
    }

    // validation tracepoints
    let map_validation_block_connected = find_map(&obj, "validation_block_connected")?;
    if !args.no_validation_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_VALIDATION);
        ringbuff_builder.add(&map_validation_block_connected, |data| {
            handle_validation_block_connected(data, &nc)
        })?;
    }

    // mempool tracepoints
    let map_mempool_added = find_map(&obj, "mempool_added")?;
    let map_mempool_removed = find_map(&obj, "mempool_removed")?;
    let map_mempool_rejected = find_map(&obj, "mempool_rejected")?;
    let map_mempool_replaced = find_map(&obj, "mempool_replaced")?;
    if !args.no_mempool_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_MEMPOOL);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        ringbuff_builder
            .add(&map_mempool_added,    |data| { handle_mempool_added(data, &nc) })?
            .add(&map_mempool_removed,  |data| { handle_mempool_removed(data, &nc) })?
            .add(&map_mempool_rejected, |data| { handle_mempool_rejected(data, &nc) })?
            .add(&map_mempool_replaced, |data| { handle_mempool_replaced(data, &nc) })?;
    }

    // addrman tracepoints
    let map_addrman_insert_new = find_map(&obj, "addrman_insert_new")?;
    let map_addrman_insert_tried = find_map(&obj, "addrman_insert_tried")?;
    if args.addrman_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_ADDRMAN);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        ringbuff_builder
            .add(&map_addrman_insert_new, |data| { handle_addrman_new(data, &nc) })?
            .add(&map_addrman_insert_tried, |data| { handle_addrman_tried(data, &nc) })?;
    }

    if active_tracepoints.is_empty() {
        log::error!("No tracepoints enabled.");
        return Ok(());
    }

    // attach tracepoints
    let mut _links = Vec::new();
    for tracepoint in active_tracepoints {
        let prog = find_prog_mut(&obj, tracepoint.function)?;
        _links.push(prog.attach_usdt(
            pid,
            &args.bitcoind_path,
            tracepoint.context,
            tracepoint.name,
        )?);
        log::info!(
            "hooked the BPF script function {} up to the tracepoint {}:{} of '{}' with PID={}",
            tracepoint.function,
            tracepoint.context,
            tracepoint.name,
            args.bitcoind_path,
            pid
        );
    }

    let ring_buffers = ringbuff_builder.build()?;
    log::info!(
        "Startup successful. Starting to extract events from '{}'..",
        args.bitcoind_path
    );
    let mut last_event_timestamp = SystemTime::now();
    let mut has_warned_about_no_events = false;
    loop {
        match ring_buffers.poll_raw(Duration::from_secs(1)) {
            RINGBUFF_CALLBACK_OK => (),
            RINGBUFF_CALLBACK_UNABLE_TO_PARSE_P2P_MSG => log::warn!("Could not parse P2P message."),
            RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR => log::warn!("SystemTimeError"),
            _other => {
                // values >0 are the number of handled events
                if _other <= 0 {
                    log::warn!("Unhandled ringbuffer callback error: {}", _other)
                } else {
                    last_event_timestamp = SystemTime::now();
                    has_warned_about_no_events = false;
                    log::trace!(
                        "Extracted {} event{} from ring buffers and tried to publish {}",
                        _other,
                        if _other > 1 { "s" } else { "" },
                        if _other > 1 { "them" } else { "it" },
                    );
                }
            }
        };
        let duration_since_last_event = SystemTime::now().duration_since(last_event_timestamp)?;
        if duration_since_last_event >= NO_EVENTS_ERROR_DURATION {
            log::error!(
                "No events received in the last {:?}.",
                NO_EVENTS_ERROR_DURATION
            );
            log::warn!("The bitcoind process might be down, has restarted and changed PIDs, or the network might be down.");
            if !args.no_idle_exit {
                log::warn!("The extractor will exit. Please restart it");
                return Ok(());
            }
            last_event_timestamp = SystemTime::now();
            has_warned_about_no_events = false;
        } else if duration_since_last_event >= NO_EVENTS_WARN_DURATION
            && !has_warned_about_no_events
        {
            has_warned_about_no_events = true;
            log::warn!(
                "No events received in the last {:?}. Is bitcoind or the network down?",
                NO_EVENTS_WARN_DURATION
            );
        }
    }
}

fn handle_net_conn_closed(data: &[u8], nc: &async_nats::Client) -> i32 {
    let closed = ClosedConnection::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::Closed(closed.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetConn.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_net_conn_closed': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_net_conn_outbound(data: &[u8], nc: &async_nats::Client) -> i32 {
    let outbound = OutboundConnection::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::Outbound(
                outbound.into(),
            )),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetConn.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_net_conn_outbound': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_net_conn_inbound(data: &[u8], nc: &async_nats::Client) -> i32 {
    let inbound = InboundConnection::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::Inbound(inbound.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };

    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetConn.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_net_conn_inbound': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_net_conn_inbound_evicted(data: &[u8], nc: &async_nats::Client) -> i32 {
    let evicted = ClosedConnection::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::InboundEvicted(
                evicted.into(),
            )),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };

    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetConn.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_net_conn_inbound_evicted': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_net_conn_misbehaving(data: &[u8], nc: &async_nats::Client) -> i32 {
    let misbehaving = MisbehavingConnection::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(connection::connection_event::Event::Misbehaving(
                misbehaving.into(),
            )),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };

    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetConn.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_net_conn_misbehaving': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_net_message(data: &[u8], nc: &async_nats::Client) -> i32 {
    let message = P2PMessage::from_bytes(data);
    let protobuf_message = match message.decode_to_protobuf_network_message() {
        Ok(msg) => msg.into(),
        Err(e) => {
            log::warn!("Could not parse P2P msg with size={}: {}", data.len(), e);
            return RINGBUFF_CALLBACK_UNABLE_TO_PARSE_P2P_MSG;
        }
    };
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: message.meta.create_protobuf_metadata(),
            msg: Some(protobuf_message),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::NetMsg.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!("could not publish message in 'handle_net_message': {}", e);
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_addrman_new(data: &[u8], nc: &async_nats::Client) -> i32 {
    let new = AddrmanInsertNew::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Addrman(addrman::AddrmanEvent {
            event: Some(addrman::addrman_event::Event::New(new.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Addrman.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!("could not publish message in 'handle_addrman_new': {}", e);
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_addrman_tried(data: &[u8], nc: &async_nats::Client) -> i32 {
    let tried = AddrmanInsertTried::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Addrman(addrman::AddrmanEvent {
            event: Some(addrman::addrman_event::Event::Tried(tried.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Addrman.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!("could not publish message in 'handle_addrman_tried': {}", e);
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_mempool_added(data: &[u8], nc: &async_nats::Client) -> i32 {
    let added = MempoolAdded::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
            event: Some(mempool::mempool_event::Event::Added(added.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Mempool.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!("could not publish message in 'handle_mempool_added': {}", e);
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_mempool_removed(data: &[u8], nc: &async_nats::Client) -> i32 {
    let removed = MempoolRemoved::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
            event: Some(mempool::mempool_event::Event::Removed(removed.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Mempool.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_mempool_removed': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_mempool_replaced(data: &[u8], nc: &async_nats::Client) -> i32 {
    let replaced = MempoolReplaced::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
            event: Some(mempool::mempool_event::Event::Replaced(replaced.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Mempool.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_mempool_replaced': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_mempool_rejected(data: &[u8], nc: &async_nats::Client) -> i32 {
    let rejected = MempoolRejected::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
            event: Some(mempool::mempool_event::Event::Rejected(rejected.into())),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(Subject::Mempool.to_string(), proto.encode_to_vec().into())
            .await
        {
            error!(
                "could not publish message in 'handle_mempool_rejected': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}

fn handle_validation_block_connected(data: &[u8], nc: &async_nats::Client) -> i32 {
    let connected = ValidationBlockConnected::from_bytes(data);
    let proto = match Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Validation(validation::ValidationEvent {
            event: Some(validation::validation_event::Event::BlockConnected(
                connected.into(),
            )),
        })),
    })) {
        Ok(p) => p,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let nc = nc.clone();
    tokio::spawn(async move {
        if let Err(e) = nc
            .publish(
                Subject::Validation.to_string(),
                proto.encode_to_vec().into(),
            )
            .await
        {
            error!(
                "could not publish message in 'handle_validation_block_connected': {}",
                e
            );
        }
    });
    return RINGBUFF_CALLBACK_OK;
}
