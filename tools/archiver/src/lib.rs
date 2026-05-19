#![cfg_attr(feature = "strict", deny(warnings))]

mod error;

pub use error::RuntimeError;

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use time::macros::format_description;
use time::OffsetDateTime;

use sha2::{Digest, Sha256};
use shared::serde::Serialize;

use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::nats_util;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::tokio::sync::watch;
use shared::zstd;

const MAGIC: [u8; 2] = *b"PA";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 16;
include!(concat!(env!("OUT_DIR"), "/git_hash.rs"));

struct ArchiveHeader {
    magic: [u8; 2],
    version: u8,
    git_hash: [u8; 4],
    reserved: [u8; 9],
}

impl ArchiveHeader {
    fn new(git_hash: [u8; 4]) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            git_hash,
            reserved: [0u8; 9],
        }
    }

    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.magic);
        buf[2] = self.version;
        buf[3..7].copy_from_slice(&self.git_hash);
        buf[7..16].copy_from_slice(&self.reserved);
        buf
    }
}

#[derive(Serialize)]
#[serde(crate = "shared::serde")]
struct FileEntry {
    name: String,
    version: u8,
    nats_address: String,
    size_bytes: u64,
    events: u64,
    first_timestamp: u64,
    last_timestamp: u64,
    event_types: Vec<String>,
    checksum: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_checksum: Option<String>,
}

struct TrackingWriter {
    inner: BufWriter<File>,
    hasher: Sha256,
    bytes_written: u64,
}

impl Write for TrackingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct CompressedStats {
    checksum: String,
    size_bytes: u64,
}

enum ArchiveWriter {
    Plain(BufWriter<File>),
    Zstd(zstd::Encoder<'static, TrackingWriter>),
}

impl ArchiveWriter {
    fn new(file: File, compression_level: u32) -> std::io::Result<Self> {
        if compression_level > 0 {
            let tracker = TrackingWriter {
                inner: BufWriter::new(file),
                hasher: Sha256::new(),
                bytes_written: 0,
            };
            let encoder = zstd::Encoder::new(tracker, compression_level as i32)?;
            Ok(Self::Zstd(encoder))
        } else {
            Ok(Self::Plain(BufWriter::new(file)))
        }
    }

    fn compressed_bytes(&self) -> Option<u64> {
        match self {
            Self::Plain(_) => None,
            Self::Zstd(encoder) => Some(encoder.get_ref().bytes_written),
        }
    }

    fn finish(self) -> std::io::Result<Option<CompressedStats>> {
        match self {
            Self::Plain(mut writer) => {
                writer.flush()?;
                Ok(None)
            }
            Self::Zstd(encoder) => {
                let mut tracker = encoder.finish()?;
                tracker.flush()?;
                Ok(Some(CompressedStats {
                    size_bytes: tracker.bytes_written,
                    checksum: format!("{:x}", tracker.hasher.finalize()),
                }))
            }
        }
    }
}

impl Write for ArchiveWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(buf),
            Self::Zstd(encoder) => encoder.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Zstd(encoder) => encoder.flush(),
        }
    }
}

/// Holds all mutable state for the currently open archive file.
/// Tracks bytes written, event counts, timestamps, and event types
/// so that the main event loop only needs to call write_event() and
/// check needs_rotation().
struct ArchiveFile {
    path: PathBuf,
    formatted_timestamp: String,
    writer: ArchiveWriter,
    hasher: Sha256,
    bytes_written: u64,
    events: u64,
    first_timestamp: u64,
    last_timestamp: u64,
    event_types: HashSet<&'static str>,
}

impl ArchiveFile {
    fn new(output_dir: &Path, base_name: &str, compression_level: u32) -> std::io::Result<Self> {
        let ext = if compression_level > 0 {
            "bin.zst"
        } else {
            "bin"
        };
        // Retry on rare timestamp collisions (e.g. fast rotations in tests)
        let (path, formatted_timestamp, file) = loop {
            let formatted_timestamp = format_utc_timestamp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            );
            let path = output_dir.join(format!("{}.{}.{}", base_name, formatted_timestamp, ext));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => break (path, formatted_timestamp, file),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!("failed to create archive {}: {}", path.display(), e),
                    ));
                }
            }
        };
        let mut writer = ArchiveWriter::new(file, compression_level)?;
        let mut hasher = Sha256::new();
        // header: 16 bytes = MAGIC "PA" (2B) + VERSION (1B) + GIT_HASH (4B) + reserved (9B)
        let header_bytes = ArchiveHeader::new(GIT_HASH).to_bytes();
        writer.write_all(&header_bytes)?;
        hasher.update(header_bytes);
        writer.flush()?;
        Ok(Self {
            path,
            formatted_timestamp,
            writer,
            hasher,
            bytes_written: HEADER_SIZE as u64,
            events: 0,
            first_timestamp: 0,
            last_timestamp: 0,
            event_types: HashSet::new(),
        })
    }

    fn write_event(&mut self, event: &Event) -> std::io::Result<()> {
        let buf = event.encode_length_delimited_to_vec();
        self.writer.write_all(&buf)?;
        self.hasher.update(&buf);
        self.bytes_written += buf.len() as u64;
        self.events += 1;
        if self.first_timestamp == 0 {
            self.first_timestamp = event.timestamp;
        }
        self.last_timestamp = event.timestamp;
        if let Some(name) = event_type_name(event) {
            self.event_types.insert(name);
        }
        Ok(())
    }

    fn needs_rotation(&self, max_file_size: u64) -> bool {
        match self.writer.compressed_bytes() {
            Some(size) => size >= max_file_size,
            None => self.bytes_written >= max_file_size,
        }
    }

    fn finalize(self, name: String, nats_address: &str) -> std::io::Result<FileEntry> {
        let compressed_stats = self.writer.finish()?;
        let checksum = format!("{:x}", self.hasher.finalize());
        let mut sorted_types: Vec<String> =
            self.event_types.into_iter().map(String::from).collect();
        sorted_types.sort();
        let entry = FileEntry {
            name,
            version: VERSION,
            nats_address: nats_address.to_string(),
            size_bytes: self.bytes_written,
            events: self.events,
            first_timestamp: self.first_timestamp,
            last_timestamp: self.last_timestamp,
            event_types: sorted_types,
            checksum,
            compressed_size_bytes: compressed_stats.as_ref().map(|s| s.size_bytes),
            compressed_checksum: compressed_stats.map(|s| s.checksum),
        };
        Ok(entry)
    }
}

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Archive peer-observer events to disk")]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// Output directory for archive files.
    #[arg(short, long)]
    pub output_dir: PathBuf,

    /// Base name for archive files (e.g., "mainnet" -> "mainnet.<timestamp>.bin.zst").
    #[arg(short, long, default_value = "archive")]
    pub base_name: String,

    /// Maximum compressed output size in bytes before rotation (default: 1GB).
    #[arg(long, default_value_t = 1_073_741_824)]
    pub max_file_size: u64,

    /// The log level the tool should run on.
    #[arg(short, long, default_value_t = log::Level::Info)]
    pub log_level: log::Level,

    /// If passed, archive P2P message events.
    #[arg(long)]
    pub messages: bool,

    /// If passed, archive P2P connection events.
    #[arg(long)]
    pub connections: bool,

    /// If passed, archive mempool events.
    #[arg(long)]
    pub mempool: bool,

    /// If passed, archive validation events.
    #[arg(long)]
    pub validation: bool,

    /// If passed, archive RPC events.
    #[arg(long)]
    pub rpc: bool,

    /// If passed, archive p2p-extractor events.
    #[arg(long)]
    pub p2p_extractor: bool,

    /// If passed, archive log-extractor events.
    #[arg(long)]
    pub log_extractor: bool,

    /// If passed, archive ipc-extractor events.
    #[arg(long)]
    pub ipc_extractor: bool,

    /// Zstd compression level (0 = no compression, 1-22). Default: 22 (ultra).
    #[arg(long, default_value_t = 22)]
    pub compression_level: u32,
}

impl Args {
    /// Returns true if all event types should be archived (no filters specified).
    pub fn archive_all(&self) -> bool {
        !(self.messages
            || self.connections
            || self.mempool
            || self.validation
            || self.rpc
            || self.p2p_extractor
            || self.log_extractor
            || self.ipc_extractor)
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    if args.archive_all() {
        log::info!("archiving all events: {}", args.archive_all());
    } else {
        log::info!("archiving all events:           {}", args.archive_all());
        log::info!("archiving P2P messages:         {}", args.messages);
        log::info!("archiving P2P connections:      {}", args.connections);
        log::info!("archiving mempool events:       {}", args.mempool);
        log::info!("archiving validation events:    {}", args.validation);
        log::info!("archiving rpc events:           {}", args.rpc);
        log::info!("archiving p2p_extractor events: {}", args.p2p_extractor);
        log::info!("archiving log_extractor events: {}", args.log_extractor);
        log::info!("archiving ipc_extractor events: {}", args.ipc_extractor);
    }

    let nc = nats_util::prepare_connection(&args.nats)?
        .connect(&args.nats.address)
        .await?;

    let mut sub = nc.subscribe("*").await?;
    log::info!("Connected to NATS-server at {}", args.nats.address);

    fs::create_dir_all(&args.output_dir)?;
    let mut current_file =
        ArchiveFile::new(&args.output_dir, &args.base_name, args.compression_level)?;
    log::info!("Created archive file: {}", current_file.path.display());

    let mut total_events: u64 = 0;
    let mut total_files: u64 = 0;

    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {
                if let Some(msg) = maybe_msg {
                    let event = match Event::decode(msg.payload.as_ref()) {
                        Ok(event) => event,
                        Err(e) => {
                            log::warn!("failed to decode event: {}, skipping", e);
                            continue;
                        }
                    };
                    if should_archive(&event, &args){
                        if let Err(e) = current_file.write_event(&event) {
                            log::error!("failed to write event: {}", e);
                            break;
                        }

                        if current_file.needs_rotation(args.max_file_size) {
                            match rotate(current_file, &args) {
                                Ok((file_events, new_file)) => {
                                    total_events += file_events;
                                    total_files += 1;
                                    current_file = new_file;
                                }
                                Err(e) => {
                                    log::error!("failed to rotate archive: {}", e);
                                    return Err(e.into());
                                }
                            }
                        }
                    }
                } else {
                    break; // subscription ended
                }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("archiver tool received shutdown signal.");
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

    total_events += close_file(current_file, &args)?;
    total_files += 1;

    log::info!(
        "shutting down. total events archived: {}, files: {}",
        total_events,
        total_files
    );
    Ok(())
}

/// Finalizes the current archive file, adds its FileEntry to the manifest,
/// and writes the manifest to disk.
fn close_file(current_file: ArchiveFile, args: &Args) -> std::io::Result<u64> {
    let name = current_file
        .path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let manifest_path = args.output_dir.join(format!(
        "{}.{}.manifest.toml",
        args.base_name, current_file.formatted_timestamp
    ));
    let entry = current_file.finalize(name, &args.nats.address)?;

    write_manifest(&entry, &manifest_path)?;
    Ok(entry.events)
}

/// Closes the current archive file and opens the next one.
fn rotate(current_file: ArchiveFile, args: &Args) -> std::io::Result<(u64, ArchiveFile)> {
    let total_events = close_file(current_file, args)?;
    let new_file = ArchiveFile::new(&args.output_dir, &args.base_name, args.compression_level)?;
    Ok((total_events, new_file))
}

fn should_archive(event: &Event, args: &Args) -> bool {
    if args.archive_all() {
        return true;
    }
    match event_type_name(event) {
        Some("messages") => args.messages,
        Some("connections") => args.connections,
        Some("mempool") => args.mempool,
        Some("validation") => args.validation,
        Some("rpc") => args.rpc,
        Some("p2p_extractor") => args.p2p_extractor,
        Some("log_extractor") => args.log_extractor,
        Some("ipc_extractor") => args.ipc_extractor,
        _ => false,
    }
}

fn event_type_name(event: &Event) -> Option<&'static str> {
    let name = match event.peer_observer_event.as_ref()? {
        PeerObserverEvent::EbpfExtractor(e) => match e.ebpf_event.as_ref()? {
            ebpf::EbpfEvent::Message(_) => "messages",
            ebpf::EbpfEvent::Connection(_) => "connections",
            ebpf::EbpfEvent::Mempool(_) => "mempool",
            ebpf::EbpfEvent::Validation(_) => "validation",
        },
        PeerObserverEvent::RpcExtractor(_) => "rpc",
        PeerObserverEvent::P2pExtractor(_) => "p2p_extractor",
        PeerObserverEvent::LogExtractor(_) => "log_extractor",
        PeerObserverEvent::IpcExtractor(_) => "ipc_extractor",
    };
    Some(name)
}

fn write_manifest(entry: &FileEntry, path: &Path) -> std::io::Result<()> {
    let toml_str = toml::to_string_pretty(entry).map_err(std::io::Error::other)?;
    fs::write(path, &toml_str)?;
    log::info!("wrote manifest: {}", path.display());
    Ok(())
}

fn format_utc_timestamp(epoch_ms: u64) -> String {
    let fmt = format_description!("[year][month][day]-[hour][minute][second]-[subsecond digits:3]");
    OffsetDateTime::from_unix_timestamp_nanos(epoch_ms as i128 * 1_000_000)
        .expect("timestamp out of range")
        .format(&fmt)
        .expect("timestamp formatting failed")
}
