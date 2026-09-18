#![cfg_attr(feature = "strict", deny(warnings))]

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, Map, MapCore, MapFlags, Object, ProgramMut, RingBuffer, RingBufferBuilder};
use shared::anyhow::{bail, Context, Result};
use shared::clap::Parser;
use shared::log::{self, error};
use shared::nats_subjects::Subject;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::ctypes::{
    ClosedConnection, InboundConnection, MempoolAdded, MempoolRejected, MempoolRemoved,
    MempoolReplaced, MisbehavingConnection, OutboundConnection, P2PMessage,
    ValidationBlockConnected,
};
use shared::protobuf::ebpf_extractor::{connection, ebpf, mempool, message, validation, Ebpf};
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::tokio::sync::{mpsc, watch};
use shared::{async_nats, clap, nats_util, tokio};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::SystemTime;

#[path = "tracing.gen.rs"]
mod tracing;

const RINGBUFF_CALLBACK_OK: i32 = 0;
const RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR: i32 = -5;
const RINGBUFF_CALLBACK_UNABLE_TO_PARSE_P2P_MSG: i32 = -20;

/// How many encoded events may wait to be published before we start dropping
/// them. Publishing runs in its own task so that reading from the ring buffers
/// never has to wait for the NATS server.
const PUBLISH_QUEUE_SIZE: usize = 8192;

/// Events we could not hand to the publisher task because its queue was full.
static UNPUBLISHED_EVENTS: AtomicU64 = AtomicU64::new(0);

const NO_EVENTS_ERROR_DURATION: Duration = Duration::from_secs(60 * 3);
const NO_EVENTS_WARN_DURATION: Duration = Duration::from_secs(60);

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
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// Path to the Bitcoin Core (bitcoind) binary that should be hooked into.
    #[arg(short, long)]
    pub bitcoind_path: String,

    /// PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into.
    /// Either this or --bitcoind-pid-file must be set.
    #[arg(long)]
    pub bitcoind_pid: Option<i32>,

    /// File containing the PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into.
    /// Either this or --bitcoind-pid must be set.
    #[arg(long)]
    pub bitcoind_pid_file: Option<String>,

    // Default tracepoints
    /// Controls if the p2p message tracepoints should be hooked into.
    #[arg(long)]
    pub no_p2pmsg_tracepoints: bool,
    /// Controls if the connection tracepoints should be hooked into.
    #[arg(long)]
    pub no_connection_tracepoints: bool,
    /// Controls if the mempool tracepoints should be hooked into.
    #[arg(long)]
    pub no_mempool_tracepoints: bool,
    /// Controls if the validation tracepoints should be hooked into.
    #[arg(long)]
    pub no_validation_tracepoints: bool,

    /// The log level the extractor should run with. Valid log levels are "trace",
    /// "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html
    #[arg(short, long, default_value_t = log::Level::Debug)]
    pub log_level: log::Level,

    /// If used, libbpf will print debug information about the BPF maps,
    /// programs, and tracepoints during extractor startup. This can be
    /// useful during debugging.
    #[arg(long, default_value_t = false)]
    pub libbpf_debug: bool,

    /// The ebpf-extractor will exit if it doesn't detect activity in the ebpf
    /// buffers for 180 seconds. This flag disables this and only emits warnings
    /// about inactivity. This can be useful during debugging.
    #[arg(short = 'i', long)]
    pub no_idle_exit: bool,
}

impl Args {
    fn no_tracepoints_enabled(&self) -> bool {
        self.no_p2pmsg_tracepoints
            && self.no_connection_tracepoints
            && self.no_validation_tracepoints
            && self.no_mempool_tracepoints
    }
}

struct LogDropCall<T: Sized> {
    name: String,
    inner: T,
}

impl<T> LogDropCall<T> {
    fn new(name: &str, inner: T) -> Self {
        Self {
            name: name.to_string(),
            inner,
        }
    }
}

impl<T> Deref for LogDropCall<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T> DerefMut for LogDropCall<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T> Drop for LogDropCall<T> {
    fn drop(&mut self) {
        log::debug!("Dropped {}", self.name);
    }
}

/// Queries procfs to see if the process with the given pid exists
fn process_exists(pid: i32) -> bool {
    Path::new(&format!("/proc/{}/stat", pid)).exists()
}

/// Find the BPF program with the given name
pub fn find_prog_mut<'obj>(object: &'obj Object, name: &str) -> Result<ProgramMut<'obj>> {
    match object.progs_mut().find(|prog| prog.name() == name) {
        Some(prog) => Ok(prog),
        None => bail!("could not find the BPF program {name}"),
    }
}

/// Find the BPF map with the given name
pub fn find_map<'obj>(object: &'obj Object, name: &str) -> Result<Map<'obj>> {
    match object.maps().find(|map| map.name() == name) {
        Some(map) => Ok(map),
        None => bail!("could not find the BPF map {name}"),
    }
}

/// Errors that are expected to be transient while bitcoind is (re)starting:
/// the process might not be running (yet), or its pid file might not exist
/// (yet). The run loop swallows these and keeps retrying instead of exiting.
///
/// These are attached as `anyhow` context so they keep their underlying source
/// error while staying discoverable via `downcast_ref`.
#[derive(Debug)]
enum TransientStartupError {
    NoProcessWithPid(i32),
    NoPidFile(String),
}

impl fmt::Display for TransientStartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransientStartupError::NoProcessWithPid(pid) => {
                write!(f, "could not find process with PID {pid}")
            }
            TransientStartupError::NoPidFile(path) => {
                write!(f, "could not open pid file from {path}")
            }
        }
    }
}

impl std::error::Error for TransientStartupError {}

/// Returns the bitcoind pid from the args or from the file supplied in the args
fn bitcoind_pid(args: &Args) -> Result<i32> {
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

    let file = File::open(&path).with_context(|| TransientStartupError::NoPidFile(path.clone()))?;
    let mut reader = BufReader::new(file);
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .with_context(|| format!("reading pid file from {path}"))?;
    let pid: i32 = content
        .trim()
        .parse()
        .with_context(|| format!("parsing the pid from pid file {path}"))?;
    Ok(pid)
}

/// Returns true if the pid returned by the `bitcoin_pid` function
/// comes from a bitcoin pid file.
fn pid_comes_from_file(args: &Args) -> bool {
    args.bitcoind_pid.is_none() && args.bitcoind_pid_file.is_some()
}

/// Returns the pid of the bitcoind process, by deriving it from the args. It also checks
/// that the process with that pid exists.
fn try_get_running_process_pid(args: &Args) -> Result<i32> {
    let pid = bitcoind_pid(args)?;

    if process_exists(pid) {
        if pid_comes_from_file(args) {
            log::info!(
                "Using bitcoind PID={} read from {}",
                pid,
                args.bitcoind_pid_file.as_ref().unwrap()
            );
        } else {
            log::info!("Using bitcoind PID={}", pid);
        }
        Ok(pid)
    } else {
        Err(TransientStartupError::NoProcessWithPid(pid).into())
    }
}

/// Names for the slots of the `dropped_events` BPF map. Must stay in sync
/// with the DROP_* defines in tracing.bpf.c.
const DROPPED_EVENT_NAMES: [&str; 16] = [
    "small P2P message, buffer full",
    "medium P2P message, buffer full",
    "large P2P message, buffer full",
    "huge P2P message, buffer full",
    "P2P message, too big for us",
    "inbound connection, buffer full",
    "outbound connection, buffer full",
    "closed connection, buffer full",
    "evicted inbound connection, buffer full",
    "misbehaving connection, buffer full",
    "mempool added, buffer full",
    "mempool removed, buffer full",
    "mempool replaced, buffer full",
    "mempool rejected, buffer full",
    "block connected, buffer full",
    "P2P message, could not read it from bitcoind",
];

/// How often we report events that bitcoind produced faster than we could
/// read them.
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Reads how many events the BPF programs had to drop so far. The counters
/// are kept per CPU, so we sum them up.
fn read_dropped_events(object: &Object) -> Result<[u64; DROPPED_EVENT_NAMES.len()]> {
    let map = find_map(object, "dropped_events")?;
    let mut totals = [0u64; DROPPED_EVENT_NAMES.len()];
    for (slot, total) in totals.iter_mut().enumerate() {
        let per_cpu = map
            .lookup_percpu(&(slot as u32).to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("looking up the drop counter of slot {slot}"))?
            .unwrap_or_default();
        for value in per_cpu {
            let counter: [u8; 8] = value
                .get(..8)
                .and_then(|bytes| bytes.try_into().ok())
                .context("drop counter is too short")?;
            *total = total.saturating_add(u64::from_ne_bytes(counter));
        }
    }
    Ok(totals)
}

/// Warns about events dropped since the last report.
fn report_dropped_events(
    object: &Object,
    previous: &mut [u64; DROPPED_EVENT_NAMES.len()],
    previously_unpublished: &mut u64,
) {
    let unpublished = UNPUBLISHED_EVENTS.load(Ordering::Relaxed);
    let new_unpublished = unpublished.saturating_sub(*previously_unpublished);
    if new_unpublished > 0 {
        log::warn!(
            "Dropped {} event{} in the last {:?} (could not publish them fast enough).",
            new_unpublished,
            if new_unpublished > 1 { "s" } else { "" },
            DROP_REPORT_INTERVAL,
        );
    }
    *previously_unpublished = unpublished;

    let current = match read_dropped_events(object) {
        Ok(current) => current,
        Err(e) => {
            log::warn!("Could not read the dropped event counters: {:#}", e);
            return;
        }
    };
    for (slot, name) in DROPPED_EVENT_NAMES.iter().enumerate() {
        let dropped = current[slot].saturating_sub(previous[slot]);
        if dropped > 0 {
            log::warn!(
                "Dropped {} event{} in the last {:?} ({}).",
                dropped,
                if dropped > 1 { "s" } else { "" },
                DROP_REPORT_INTERVAL,
                name,
            );
        }
    }
    *previous = current;
}

/// Tells libbpf to skip the BPF programs and ring buffers of the tracepoint
/// groups that are turned off. Ring buffers are created even when nobody
/// reads from them, and the kernel reserves their memory right away, so the
/// P2P message ones in particular are worth leaving out.
fn skip_disabled_tracepoints(skel: &mut tracing::OpenTracingSkel, args: &Args) -> Result<()> {
    if args.no_p2pmsg_tracepoints {
        skel.progs.handle_net_msg_inbound.set_autoload(false);
        skel.progs.handle_net_msg_outbound.set_autoload(false);
        skel.maps.net_msg_small.set_autocreate(false)?;
        skel.maps.net_msg_medium.set_autocreate(false)?;
        skel.maps.net_msg_large.set_autocreate(false)?;
        skel.maps.net_msg_huge.set_autocreate(false)?;
    }
    if args.no_connection_tracepoints {
        skel.progs.handle_net_conn_inbound.set_autoload(false);
        skel.progs.handle_net_conn_outbound.set_autoload(false);
        skel.progs.handle_net_conn_closed.set_autoload(false);
        skel.progs
            .handle_net_conn_inbound_evicted
            .set_autoload(false);
        skel.progs.handle_net_conn_misbehaving.set_autoload(false);
        skel.maps.net_conn_inbound.set_autocreate(false)?;
        skel.maps.net_conn_outbound.set_autocreate(false)?;
        skel.maps.net_conn_closed.set_autocreate(false)?;
        skel.maps.net_conn_inbound_evicted.set_autocreate(false)?;
        skel.maps.net_conn_misbehaving.set_autocreate(false)?;
    }
    if args.no_mempool_tracepoints {
        skel.progs.handle_mempool_added.set_autoload(false);
        skel.progs.handle_mempool_removed.set_autoload(false);
        skel.progs.handle_mempool_replaced.set_autoload(false);
        skel.progs.handle_mempool_rejected.set_autoload(false);
        skel.maps.mempool_added.set_autocreate(false)?;
        skel.maps.mempool_removed.set_autocreate(false)?;
        skel.maps.mempool_replaced.set_autocreate(false)?;
        skel.maps.mempool_rejected.set_autocreate(false)?;
    }
    if args.no_validation_tracepoints {
        skel.progs
            .handle_validation_block_connected
            .set_autoload(false);
        skel.maps.validation_block_connected.set_autocreate(false)?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
fn init_bpf_listener<'a, 'b>(
    args: &Args,
    pid: i32,
    requests: &'a mpsc::Sender<PublishRequest>,
    obj_container: &'b mut MaybeUninit<libbpf_rs::OpenObject>,
) -> Result<(
    i32,
    LogDropCall<tracing::TracingSkel<'b>>,
    LogDropCall<RingBuffer<'a>>,
    LogDropCall<Vec<Link>>,
)> {
    let mut skel_builder = tracing::TracingSkelBuilder::default();
    skel_builder.obj_builder.debug(args.libbpf_debug);
    log::info!("Opening BPF skeleton with debug={}..", args.libbpf_debug);
    let mut open_skel: tracing::OpenTracingSkel = skel_builder
        .open(obj_container)
        .context("opening the BPF skeleton")?;
    skip_disabled_tracepoints(&mut open_skel, args)?;
    log::info!("Loading BPF functions and maps into kernel..");
    let skel: tracing::TracingSkel = open_skel
        .load()
        .context("loading the BPF programs and maps into the kernel")?;
    let obj = skel.object();

    // Update the ebpf-extractor docs in the README.md when editing the active_tracepoints.
    let mut active_tracepoints = vec![];
    let mut ringbuff_builder = RingBufferBuilder::new();

    // P2P net msgs tracepoints
    let map_net_msg_small = find_map(obj, "net_msg_small")?;
    let map_net_msg_medium = find_map(obj, "net_msg_medium")?;
    let map_net_msg_large = find_map(obj, "net_msg_large")?;
    let map_net_msg_huge = find_map(obj, "net_msg_huge")?;
    if !args.no_p2pmsg_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_NET_MESSAGE);
        #[rustfmt::skip]
        ringbuff_builder
            .add(&map_net_msg_small,    |data| { handle_net_message(data, requests) })?
            .add(&map_net_msg_medium,   |data| { handle_net_message(data, requests) })?
            .add(&map_net_msg_large,    |data| { handle_net_message(data, requests) })?
            .add(&map_net_msg_huge,     |data| { handle_net_message(data, requests) })?;
    }

    // P2P connection tracepoints
    let map_net_conn_inbound = find_map(obj, "net_conn_inbound")?;
    let map_net_conn_outbound = find_map(obj, "net_conn_outbound")?;
    let map_net_conn_closed = find_map(obj, "net_conn_closed")?;
    let map_net_conn_inbound_evicted = find_map(obj, "net_conn_inbound_evicted")?;
    let map_net_conn_misbehaving = find_map(obj, "net_conn_misbehaving")?;
    if !args.no_connection_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_NET_CONN);
        #[rustfmt::skip]
        ringbuff_builder
            .add(&map_net_conn_inbound,         |data| { handle_net_conn_inbound(data, requests) })?
            .add(&map_net_conn_outbound,        |data| { handle_net_conn_outbound(data, requests) })?
            .add(&map_net_conn_closed,          |data| { handle_net_conn_closed(data, requests) })?
            .add(&map_net_conn_inbound_evicted, |data| { handle_net_conn_inbound_evicted(data, requests) })?
            .add(&map_net_conn_misbehaving,     |data| { handle_net_conn_misbehaving(data, requests) })?;
    }

    // validation tracepoints
    let map_validation_block_connected = find_map(obj, "validation_block_connected")?;
    if !args.no_validation_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_VALIDATION);
        ringbuff_builder.add(&map_validation_block_connected, |data| {
            handle_validation_block_connected(data, requests)
        })?;
    }

    // mempool tracepoints
    let map_mempool_added = find_map(obj, "mempool_added")?;
    let map_mempool_removed = find_map(obj, "mempool_removed")?;
    let map_mempool_rejected = find_map(obj, "mempool_rejected")?;
    let map_mempool_replaced = find_map(obj, "mempool_replaced")?;
    if !args.no_mempool_tracepoints {
        active_tracepoints.extend(&TRACEPOINTS_MEMPOOL);
        #[rustfmt::skip]
        ringbuff_builder
            .add(&map_mempool_added,    |data| { handle_mempool_added(data, requests) })?
            .add(&map_mempool_removed,  |data| { handle_mempool_removed(data, requests) })?
            .add(&map_mempool_rejected, |data| { handle_mempool_rejected(data, requests) })?
            .add(&map_mempool_replaced, |data| { handle_mempool_replaced(data, requests) })?;
    }

    // attach tracepoints
    let mut links = Vec::new();
    for tracepoint in active_tracepoints {
        let prog = find_prog_mut(obj, tracepoint.function)?;
        links.push(prog.attach_usdt(
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

    let ring_buffers = ringbuff_builder
        .build()
        .context("building the BPF ring buffers")?;
    log::info!(
        "Startup successful. Starting to extract events from '{}'..",
        args.bitcoind_path
    );

    Ok((
        pid,
        LogDropCall::new("loaded skel", skel),
        LogDropCall::new("ring buffers", ring_buffers),
        LogDropCall::new("links vector", links),
    ))
}

pub async fn run(args: Args, shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    if args.no_tracepoints_enabled() {
        log::error!("No tracepoints enabled.");
        return Ok(());
    }

    let pid = try_get_running_process_pid(&args)?;

    let nc = nats_util::prepare_connection(&args.nats)
        .context("preparing NATS connection")?
        .connect(&args.nats.address)
        .await
        .with_context(|| format!("connecting to NATS at {}", args.nats.address))?;
    log::info!("Connected to NATS server at {}", args.nats.address);

    let (publish_requests, requests) = mpsc::channel(PUBLISH_QUEUE_SIZE);
    tokio::spawn(publish_events(nc, requests));

    let mut obj_container = MaybeUninit::uninit();
    // Keeping _loaded_obj and _links alive is important. Dropping them triggers deleletion from the
    // kernel space of the corresponding bpf maps.
    let (mut pid, mut _loaded_obj, mut ring_buffers, mut _links) =
        init_bpf_listener(&args, pid, &publish_requests, &mut obj_container)?;

    let mut last_event_timestamp = SystemTime::now();
    let mut has_warned_about_no_events = false;
    let mut last_drop_report = SystemTime::now();
    let mut reported_drops = [0u64; DROPPED_EVENT_NAMES.len()];
    let mut reported_unpublished = 0u64;
    loop {
        // Check for shutdown signal (non-blocking).
        // Max latency is ~1 second (the poll_raw timeout).
        // Treat a dropped sender (Err) as shutdown, matching the other extractors'
        // tokio::select! branches that break on Err(_) from changed().
        match shutdown_rx.has_changed() {
            Ok(true) if *shutdown_rx.borrow() => {
                log::info!("ebpf-extractor received shutdown signal.");
                return Ok(());
            }
            Err(_) => {
                log::info!("ebpf-extractor shutdown channel closed, exiting.");
                return Ok(());
            }
            _ => {}
        }

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

        if pid == 0 || !process_exists(pid) {
            if pid != 0 {
                log::info!("The bitcoind process with pid {} exited", pid);
                pid = 0;
            }

            match try_get_running_process_pid(&args) {
                Ok(new_pid) => {
                    // The order in which we drop matters. Doing it the other way might cause a
                    // use-after-free in libbpf.
                    drop(_links);
                    drop(_loaded_obj);
                    drop(ring_buffers);
                    (pid, _loaded_obj, ring_buffers, _links) =
                        init_bpf_listener(&args, new_pid, &publish_requests, &mut obj_container)
                            .context("re-initializing the BPF listener after bitcoind restart")?;
                    last_event_timestamp = SystemTime::now();
                    has_warned_about_no_events = false;
                    // The counters start over with the freshly created maps.
                    reported_drops = [0u64; DROPPED_EVENT_NAMES.len()];
                }
                // Restarting the bitcoind process can take some time, so keep
                // retrying on transient errors and only bail on real failures.
                Err(e) => {
                    if e.downcast_ref::<TransientStartupError>().is_none() {
                        return Err(e);
                    }
                }
            }
        }

        if last_drop_report.elapsed().unwrap_or_default() >= DROP_REPORT_INTERVAL {
            last_drop_report = SystemTime::now();
            report_dropped_events(
                _loaded_obj.object(),
                &mut reported_drops,
                &mut reported_unpublished,
            );
        }

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

/// An encoded event waiting to be published.
struct PublishRequest {
    subject: Subject,
    payload: Vec<u8>,
}

/// Publishes events in the order they were read out of the ring buffers.
async fn publish_events(nc: async_nats::Client, mut requests: mpsc::Receiver<PublishRequest>) {
    while let Some(request) = requests.recv().await {
        if let Err(e) = nc
            .publish(
                async_nats::Subject::from_static(request.subject.as_str()),
                request.payload.into(),
            )
            .await
        {
            error!("could not publish a {} event: {}", request.subject, e);
        }
    }
}

/// Encodes an event and hands it to the publisher task. Never waits: if the
/// publisher can't keep up we'd rather drop an event here than stall reading
/// from the ring buffers, which would make bitcoind drop events instead.
fn publish(
    requests: &mpsc::Sender<PublishRequest>,
    subject: Subject,
    event: PeerObserverEvent,
) -> i32 {
    let event = match Event::new(event) {
        Ok(event) => event,
        Err(e) => {
            error!("Could not create new Event due to SystemTimeError: {}", e);
            return RINGBUFF_CALLBACK_SYSTEM_TIME_ERROR;
        }
    };
    let request = PublishRequest {
        subject,
        payload: event.encode_to_vec(),
    };
    if requests.try_send(request).is_err() {
        // Logging each one would only add to the backlog. The count is
        // reported together with the events dropped by the BPF programs.
        UNPUBLISHED_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
    RINGBUFF_CALLBACK_OK
}

fn connection_event(event: connection::connection_event::Event) -> PeerObserverEvent {
    PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
            event: Some(event),
        })),
    })
}

fn mempool_event(event: mempool::mempool_event::Event) -> PeerObserverEvent {
    PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Mempool(mempool::MempoolEvent {
            event: Some(event),
        })),
    })
}

fn handle_net_conn_closed(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let closed = ClosedConnection::from_bytes(data);
    let event = connection::connection_event::Event::Closed(closed.into());
    publish(requests, Subject::NetConn, connection_event(event))
}

fn handle_net_conn_outbound(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let outbound = OutboundConnection::from_bytes(data);
    let event = connection::connection_event::Event::Outbound(outbound.into());
    publish(requests, Subject::NetConn, connection_event(event))
}

fn handle_net_conn_inbound(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let inbound = InboundConnection::from_bytes(data);
    let event = connection::connection_event::Event::Inbound(inbound.into());
    publish(requests, Subject::NetConn, connection_event(event))
}

fn handle_net_conn_inbound_evicted(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let evicted = ClosedConnection::from_bytes(data);
    let event = connection::connection_event::Event::InboundEvicted(evicted.into());
    publish(requests, Subject::NetConn, connection_event(event))
}

fn handle_net_conn_misbehaving(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let misbehaving = MisbehavingConnection::from_bytes(data);
    let event = connection::connection_event::Event::Misbehaving(misbehaving.into());
    publish(requests, Subject::NetConn, connection_event(event))
}

fn handle_net_message(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let message = P2PMessage::from_bytes(data);
    let protobuf_message = match message.decode_to_protobuf_network_message() {
        Ok(msg) => msg,
        Err(e) => {
            log::warn!("Could not parse P2P msg with size={}: {}", data.len(), e);
            return RINGBUFF_CALLBACK_UNABLE_TO_PARSE_P2P_MSG;
        }
    };
    let event = PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: message.meta.create_protobuf_metadata(),
            msg: Some(protobuf_message),
        })),
    });
    publish(requests, Subject::NetMsg, event)
}

fn handle_mempool_added(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let added = MempoolAdded::from_bytes(data);
    let event = mempool::mempool_event::Event::Added(added.into());
    publish(requests, Subject::Mempool, mempool_event(event))
}

fn handle_mempool_removed(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let removed = MempoolRemoved::from_bytes(data);
    let event = mempool::mempool_event::Event::Removed(removed.into());
    publish(requests, Subject::Mempool, mempool_event(event))
}

fn handle_mempool_replaced(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let replaced = MempoolReplaced::from_bytes(data);
    let event = mempool::mempool_event::Event::Replaced(replaced.into());
    publish(requests, Subject::Mempool, mempool_event(event))
}

fn handle_mempool_rejected(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let rejected = MempoolRejected::from_bytes(data);
    let event = mempool::mempool_event::Event::Rejected(rejected.into());
    publish(requests, Subject::Mempool, mempool_event(event))
}

fn handle_validation_block_connected(data: &[u8], requests: &mpsc::Sender<PublishRequest>) -> i32 {
    let connected = ValidationBlockConnected::from_bytes(data);
    let event = PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Validation(validation::ValidationEvent {
            event: Some(validation::validation_event::Event::BlockConnected(
                connected.into(),
            )),
        })),
    });
    publish(requests, Subject::Validation, event)
}
