#![cfg_attr(feature = "strict", deny(warnings))]

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::macros::format_description;
use time::OffsetDateTime;

use shared::anyhow::{Context, Result};
use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::nats_util;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::tokio::sync::{oneshot, watch};
use shared::tokio::time::Instant;
use shared::zstd;

struct TrackingWriter {
    inner: BufWriter<File>,
    bytes_written: u64,
}

impl Write for TrackingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
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

    fn finish(self) -> std::io::Result<()> {
        match self {
            Self::Plain(mut writer) => {
                writer.flush()?;
                Ok(())
            }
            Self::Zstd(encoder) => {
                let mut tracker = encoder.finish()?;
                tracker.flush()?;
                Ok(())
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
/// Tracks (compressed) bytes written so that we know when to rotate the file.
struct ArchiveFile {
    path: PathBuf,
    writer: ArchiveWriter,
    bytes_written: u64,
}

impl ArchiveFile {
    fn new(
        output_dir: &Path,
        base_name: &str,
        compression_level: u32,
        low_data: bool,
    ) -> std::io::Result<Self> {
        let ext = if compression_level > 0 {
            "bin.zst"
        } else {
            "bin"
        };
        // Retry on rare timestamp collisions (e.g. fast rotations in tests)
        let (path, file) = loop {
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
                Ok(file) => break (path, file),
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
        let header_bytes = ArchiveHeader::new(low_data).to_bytes();
        writer.write_all(&header_bytes)?;
        writer.flush()?;

        log::info!("Created archive file: {}", path.display());

        Ok(Self {
            path,
            writer,
            bytes_written: header_bytes.len() as u64,
        })
    }

    fn write_event(&mut self, event: &Event) -> std::io::Result<()> {
        let buf = event.encode_length_delimited_to_vec();
        log::trace!("writing {:?} ({} bytes)", event, buf.len());
        self.writer.write_all(&buf)?;
        self.bytes_written += buf.len() as u64;
        Ok(())
    }

    fn needs_rotation(&self, max_file_size: u64) -> bool {
        match self.writer.compressed_bytes() {
            Some(size) => size >= max_file_size,
            None => self.bytes_written >= max_file_size,
        }
    }

    fn finalize(self) -> std::io::Result<()> {
        self.writer.finish()
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

    /// If passed, don't archive raw transaction data.
    /// Requires --messages. Other enabled event filters are archived unchanged.
    /// Transactions keep their txid and wtxid. Blocks keep only their header.
    #[arg(long, requires = "messages")]
    pub low_data: bool,

    /// If passed, archive address-relay P2P messages (getaddr, addr, addrv2,
    /// including empty addrv2).
    /// Additive: combines freely with the other event filters.
    #[arg(long)]
    pub addr_relay: bool,

    /// If passed, archive P2P connections with their version handshakes:
    /// version messages (both directions) and all P2P connection events.
    /// Additive: combines freely with the other event filters.
    #[arg(long)]
    pub connections_with_handshakes: bool,
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
            || self.ipc_extractor
            || self.addr_relay
            || self.connections_with_handshakes)
    }
}

/// Per-message-type filter for P2P messages. A message is archived when its
/// type's flag is set. Extend with more message types as needed.
#[derive(Debug, Clone, Copy, Default)]
struct MessageFilter {
    getaddr: bool,
    addr: bool,
    addrv2: bool,
    version: bool,
}

impl MessageFilter {
    fn matches(&self, msg: &Msg) -> bool {
        match msg {
            Msg::Getaddr(_) => self.getaddr,
            Msg::Addr(_) => self.addr,
            // An addrv2 message without any addresses in it is emitted as its
            // own message type by the extractor.
            Msg::Addrv2(_) | Msg::Emptyaddrv2(_) => self.addrv2,
            Msg::Version(_) => self.version,
            _ => false,
        }
    }
}

/// Which events the archiver writes to disk. Derived once from the CLI args, so
/// that the filter policy lives in a single place.
#[derive(Debug, Clone, Copy, Default)]
struct ArchiveFilter {
    /// Archive every event, regardless of the per-event-type fields below.
    all: bool,
    messages: bool,
    connections: bool,
    mempool: bool,
    validation: bool,
    rpc: bool,
    p2p_extractor: bool,
    log_extractor: bool,
    ipc_extractor: bool,
    /// Archives single P2P message types that the `messages` field doesn't
    /// already cover.
    message_types: MessageFilter,
}

impl From<&Args> for ArchiveFilter {
    fn from(args: &Args) -> Self {
        Self {
            all: args.archive_all(),
            messages: args.messages,
            connections: args.connections || args.connections_with_handshakes,
            mempool: args.mempool,
            validation: args.validation,
            rpc: args.rpc,
            p2p_extractor: args.p2p_extractor,
            log_extractor: args.log_extractor,
            ipc_extractor: args.ipc_extractor,
            message_types: MessageFilter {
                getaddr: args.addr_relay,
                addr: args.addr_relay,
                addrv2: args.addr_relay,
                version: args.connections_with_handshakes,
            },
        }
    }
}

impl ArchiveFilter {
    /// Returns true if the event should be archived.
    fn matches(&self, event: &Event) -> bool {
        if self.all {
            return true;
        }
        match event.peer_observer_event.as_ref() {
            Some(PeerObserverEvent::EbpfExtractor(e)) => match e.ebpf_event.as_ref() {
                Some(ebpf::EbpfEvent::Message(message_event)) => {
                    self.messages
                        || message_event
                            .msg
                            .as_ref()
                            .is_some_and(|msg| self.message_types.matches(msg))
                }
                Some(ebpf::EbpfEvent::Connection(_)) => self.connections,
                Some(ebpf::EbpfEvent::Mempool(_)) => self.mempool,
                Some(ebpf::EbpfEvent::Validation(_)) => self.validation,
                None => false,
            },
            Some(PeerObserverEvent::RpcExtractor(_)) => self.rpc,
            Some(PeerObserverEvent::P2pExtractor(_)) => self.p2p_extractor,
            Some(PeerObserverEvent::LogExtractor(_)) => self.log_extractor,
            Some(PeerObserverEvent::IpcExtractor(_)) => self.ipc_extractor,
            None => false,
        }
    }
}

/// How long to wait for the NATS subscription to drain before shutting down
/// anyway. Draining never completes while the NATS server is unreachable, as
/// the client reconnects instead of processing the unsubscribe.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    if args.archive_all() {
        log::info!("archiving all events: {}", args.archive_all());
    } else {
        log::info!(
            "archiving all events:                  {}",
            args.archive_all()
        );
        log::info!("archiving P2P messages:                {}", args.messages);
        log::info!(
            "archiving P2P connections:             {}",
            args.connections
        );
        log::info!("archiving mempool events:              {}", args.mempool);
        log::info!("archiving validation events:           {}", args.validation);
        log::info!("archiving rpc events:                  {}", args.rpc);
        log::info!(
            "archiving p2p_extractor events:        {}",
            args.p2p_extractor
        );
        log::info!(
            "archiving log_extractor events:        {}",
            args.log_extractor
        );
        log::info!(
            "archiving ipc_extractor events:        {}",
            args.ipc_extractor
        );
        log::info!("archiving addr-relay messages:         {}", args.addr_relay);
        log::info!(
            "archiving connections-with-handshakes: {}",
            args.connections_with_handshakes
        );
    }
    log::info!("archiving in low-data mode: {}", args.low_data);

    let nc = nats_util::prepare_connection(&args.nats)
        .context("preparing NATS connection")?
        .connect(&args.nats.address)
        .await
        .with_context(|| format!("connecting to NATS at {}", args.nats.address))?;

    let mut sub = nc
        .subscribe("*")
        .await
        .context("subscribing to all NATS subjects")?;
    log::info!("Connected to NATS-server at {}", args.nats.address);

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating output directory {}", args.output_dir.display()))?;
    let mut current_file = ArchiveFile::new(
        &args.output_dir,
        &args.base_name,
        args.compression_level,
        args.low_data,
    )
    .context("creating the initial archive file")?;

    if let Some(ready_tx) = ready_tx {
        // A flush only empties the client's write buffer and does not wait for
        // the server to have processed the subscription. Prove the subscription
        // is registered by publishing a probe to an inbox subscribed on this
        // same connection: the server handles the commands of a connection in
        // order, so receiving the probe back implies the earlier "*"
        // subscription is active. The probe inbox contains dots, so it's not
        // matched by the single-token "*" subscription.
        let inbox = nc.new_inbox();
        let mut probe_sub = nc
            .subscribe(inbox.clone())
            .await
            .context("subscribing to the readiness probe inbox")?;
        nc.publish(inbox, "".into())
            .await
            .context("publishing the readiness probe")?;
        nc.flush().await.context("flushing the readiness probe")?;
        probe_sub
            .next()
            .await
            .context("receiving the readiness probe")?;
        let _ = ready_tx.send(());
    }

    let filter = ArchiveFilter::from(&args);
    let mut total_files: u64 = 0;
    let mut draining = false;
    // Only read once draining is set below.
    let mut drain_deadline = Instant::now();

    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {
                if let Some(msg) = maybe_msg {
                    let mut event = match Event::decode(msg.payload.as_ref()) {
                        Ok(event) => event,
                        Err(e) => {
                            log::warn!("failed to decode event: {}, skipping", e);
                            continue;
                        }
                    };
                    if filter.matches(&event) {
                        if args.low_data {
                            strip_low_data(&mut event);
                        }

                        if let Err(e) = current_file.write_event(&event) {
                            log::error!("failed to write event: {}", e);
                            break;
                        }

                        if current_file.needs_rotation(args.max_file_size) {
                            current_file = rotate(current_file, &args)
                                .context("rotating the archive file")?;
                            total_files += 1;
                        }
                    }
                } else {
                    break; // subscription ended
                }
            }
            res = shutdown_rx.changed(), if !draining => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("archiver tool received shutdown signal. Draining the subscription.");
                            draining = true;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Draining the subscription.");
                        draining = true;
                    }
                }
                if draining {
                    // Unsubscribes, but keeps the subscription open until all
                    // in-flight messages have been yielded. Afterwards,
                    // sub.next() returns None and the loop above breaks.
                    if let Err(e) = sub.drain().await {
                        log::warn!("failed to drain the NATS subscription: {}. Shutting down.", e);
                        break;
                    }
                    drain_deadline = Instant::now() + DRAIN_TIMEOUT;
                }
            }
            // The deadline is absolute, so re-creating this future on every
            // loop iteration doesn't extend it.
            _ = shared::tokio::time::sleep_until(drain_deadline), if draining => {
                log::warn!("draining the NATS subscription timed out. Shutting down anyway.");
                break;
            }
        }
    }

    total_files += 1;
    current_file
        .finalize()
        .context("finalizing the last archive file")?;

    log::info!("shutting down. total files: {}", total_files);
    Ok(())
}

/// Closes the current archive file and opens the next one.
fn rotate(current_file: ArchiveFile, args: &Args) -> std::io::Result<ArchiveFile> {
    log::trace!("rotating {:?}", current_file.path);
    current_file.finalize()?;
    let new_file = ArchiveFile::new(
        &args.output_dir,
        &args.base_name,
        args.compression_level,
        args.low_data,
    )?;
    Ok(new_file)
}

/// Removes the bulk of a P2P message: the raw bytes of transactions and the
/// transactions of a block. Transactions keep their txid and wtxid, blocks keep
/// their header, which includes the block hash.
/// Messages that carry no transaction payloads are left untouched.
fn strip_low_data(event: &mut Event) {
    let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = event.peer_observer_event.as_mut() else {
        return;
    };
    let Some(ebpf::EbpfEvent::Message(message_event)) = ebpf.ebpf_event.as_mut() else {
        return;
    };
    let Some(msg) = message_event.msg.as_mut() else {
        return;
    };

    match msg {
        Msg::Tx(tx) => tx.tx.raw = None,
        Msg::Block(block) => block.transactions.clear(),
        Msg::Blocktxn(blocktxn) => blocktxn
            .transactions
            .iter_mut()
            .for_each(|tx| tx.raw = None),
        Msg::Compactblock(compact_block) => compact_block
            .transactions
            .iter_mut()
            .for_each(|prefilled| prefilled.tx.raw = None),
        _ => (),
    }
}

fn format_utc_timestamp(epoch_ms: u64) -> String {
    let fmt = format_description!("[year][month][day]-[hour][minute][second]-[subsecond digits:3]");
    OffsetDateTime::from_unix_timestamp_nanos(epoch_ms as i128 * 1_000_000)
        .expect("timestamp out of range")
        .format(&fmt)
        .expect("timestamp formatting failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use shared::protobuf::bitcoin_primitives::{
        Address, BlockHeader, PrefilledTransaction, Transaction,
    };
    use shared::protobuf::ebpf_extractor::connection;
    use shared::protobuf::ebpf_extractor::message::{
        Addr, AddrV2, Block, BlockTxn, CompactBlock, Inv, MessageEvent, Metadata, Ping, Tx, Version,
    };
    use shared::protobuf::ebpf_extractor::Ebpf;

    const TXID: [u8; 32] = [0x11; 32];
    const WTXID: [u8; 32] = [0x22; 32];
    const TXID_2: [u8; 32] = [0x44; 32];
    const WTXID_2: [u8; 32] = [0x55; 32];
    const BLOCK_HASH: [u8; 32] = [0x33; 32];

    fn transaction() -> Transaction {
        transaction_with_ids(TXID, WTXID, 0xff)
    }

    fn transaction_with_ids(txid: [u8; 32], wtxid: [u8; 32], raw_byte: u8) -> Transaction {
        Transaction {
            txid: txid.to_vec(),
            wtxid: wtxid.to_vec(),
            raw: Some(vec![raw_byte; 500]),
        }
    }

    fn block_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: vec![0u8; 32],
            merkle_root: vec![0u8; 32],
            time: 1234,
            bits: 5678,
            nonce: 42,
            hash: BLOCK_HASH.to_vec(),
        }
    }

    fn message_event(msg: Msg) -> Event {
        Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                meta: Metadata {
                    peer_id: 0,
                    addr: "127.0.0.1:8333".to_string(),
                    conn_type: 1,
                    command: String::new(),
                    inbound: true,
                    size: 0,
                },
                msg: Some(msg),
            })),
        }))
        .unwrap()
    }

    /// Returns the P2P message of an event, panicking if there is none.
    fn msg_of(event: &Event) -> &Msg {
        match event.peer_observer_event.as_ref().unwrap() {
            PeerObserverEvent::EbpfExtractor(ebpf) => match ebpf.ebpf_event.as_ref().unwrap() {
                ebpf::EbpfEvent::Message(message_event) => message_event.msg.as_ref().unwrap(),
                _ => panic!("expected a P2P message event"),
            },
            _ => panic!("expected an ebpf event"),
        }
    }

    fn parse_args(args: &[&str]) -> std::result::Result<Args, clap::Error> {
        let mut argv = vec!["archiver", "--output-dir", "/tmp"];
        argv.extend_from_slice(args);
        Args::try_parse_from(argv)
    }

    fn address() -> Address {
        Address {
            timestamp: 0,
            services: 0,
            port: 8333,
            address: None,
        }
    }

    fn version_msg() -> Msg {
        Msg::Version(Version {
            version: 70016,
            services: 0,
            timestamp: 0,
            receiver: address(),
            sender: address(),
            nonce: 0,
            user_agent: "/test/".to_string(),
            start_height: 0,
            relay: false,
        })
    }

    fn connection_event() -> Event {
        Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Connection(connection::ConnectionEvent {
                event: Some(connection::connection_event::Event::Inbound(
                    connection::InboundConnection {
                        conn: connection::Connection {
                            addr: "127.0.0.1:8333".to_string(),
                            conn_type: 1,
                            network: 1,
                            peer_id: 1,
                        },
                        existing_connections: 1,
                    },
                )),
            })),
        }))
        .unwrap()
    }

    fn rpc_event() -> Event {
        Event::new(PeerObserverEvent::RpcExtractor(
            shared::protobuf::rpc_extractor::Rpc {
                rpc_event: Some(shared::protobuf::rpc_extractor::rpc::RpcEvent::Uptime(1234)),
            },
        ))
        .unwrap()
    }

    /// Runs the archive filter derived from the args on the event.
    fn archived(args: &Args, event: &Event) -> bool {
        ArchiveFilter::from(args).matches(event)
    }

    #[test]
    fn low_data_requires_messages() {
        assert!(parse_args(&["--low-data"]).is_err());
        assert!(parse_args(&["--low-data", "--messages"]).is_ok());
        assert!(parse_args(&["--low-data", "--messages", "--connections"]).is_ok());
    }

    #[test]
    fn addr_relay_and_connections_with_handshakes_combine_freely() {
        assert!(parse_args(&["--addr-relay"]).is_ok());
        assert!(parse_args(&["--connections-with-handshakes"]).is_ok());
        assert!(parse_args(&["--addr-relay", "--connections-with-handshakes"]).is_ok());
        assert!(parse_args(&[
            "--addr-relay",
            "--connections-with-handshakes",
            "--mempool",
            "--messages"
        ])
        .is_ok());
        assert!(parse_args(&[
            "--addr-relay",
            "--connections-with-handshakes",
            "--low-data",
            "--messages"
        ])
        .is_ok());
    }

    #[test]
    fn message_filter_modes_disable_archive_all() {
        assert!(parse_args(&[]).unwrap().archive_all());
        assert!(!parse_args(&["--addr-relay"]).unwrap().archive_all());
        assert!(!parse_args(&["--connections-with-handshakes"])
            .unwrap()
            .archive_all());
    }

    #[test]
    fn addr_relay_archives_only_address_relay_messages() {
        let args = parse_args(&["--addr-relay"]).unwrap();
        assert!(archived(&args, &message_event(Msg::Addr(Addr::default()))));
        assert!(archived(
            &args,
            &message_event(Msg::Addrv2(AddrV2::default()))
        ));
        assert!(archived(&args, &message_event(Msg::Getaddr(true))));
        assert!(archived(&args, &message_event(Msg::Emptyaddrv2(true))));
        assert!(!archived(&args, &message_event(version_msg())));
        assert!(!archived(&args, &message_event(Msg::Ping(Ping::default()))));
        assert!(!archived(&args, &connection_event()));
        assert!(!archived(&args, &rpc_event()));
    }

    #[test]
    fn connections_with_handshakes_archives_version_messages_and_connections() {
        let args = parse_args(&["--connections-with-handshakes"]).unwrap();
        assert!(archived(&args, &message_event(version_msg())));
        assert!(archived(&args, &connection_event()));
        assert!(!archived(&args, &message_event(Msg::Addr(Addr::default()))));
        assert!(!archived(
            &args,
            &message_event(Msg::Addrv2(AddrV2::default()))
        ));
        assert!(!archived(&args, &message_event(Msg::Getaddr(true))));
        assert!(!archived(&args, &message_event(Msg::Emptyaddrv2(true))));
        assert!(!archived(&args, &message_event(Msg::Ping(Ping::default()))));
        assert!(!archived(&args, &rpc_event()));
    }

    #[test]
    fn addr_relay_and_connections_with_handshakes_archive_the_union() {
        let args = parse_args(&["--addr-relay", "--connections-with-handshakes"]).unwrap();
        assert!(archived(&args, &message_event(Msg::Addr(Addr::default()))));
        assert!(archived(
            &args,
            &message_event(Msg::Addrv2(AddrV2::default()))
        ));
        assert!(archived(&args, &message_event(Msg::Getaddr(true))));
        assert!(archived(&args, &message_event(version_msg())));
        assert!(archived(&args, &connection_event()));
        assert!(!archived(&args, &message_event(Msg::Ping(Ping::default()))));
        assert!(!archived(&args, &rpc_event()));
    }

    #[test]
    fn messages_flag_still_archives_non_filter_messages() {
        let args = parse_args(&["--addr-relay", "--messages"]).unwrap();
        assert!(archived(&args, &message_event(Msg::Ping(Ping::default()))));
        assert!(archived(&args, &message_event(version_msg())));
        assert!(archived(&args, &message_event(Msg::Addr(Addr::default()))));
    }

    #[test]
    fn low_data_strips_tx_raw_and_keeps_ids() {
        let mut event = message_event(Msg::Tx(Tx { tx: transaction() }));

        strip_low_data(&mut event);

        let Msg::Tx(tx) = msg_of(&event) else {
            panic!("expected a tx message");
        };
        assert_eq!(tx.tx.raw, None);
        assert_eq!(tx.tx.txid, TXID.to_vec());
        assert_eq!(tx.tx.wtxid, WTXID.to_vec());
    }

    #[test]
    fn low_data_keeps_block_header_and_removes_transactions() {
        let mut event = message_event(Msg::Block(Block {
            header: block_header(),
            transactions: vec![transaction(), transaction()],
        }));

        strip_low_data(&mut event);

        let Msg::Block(block) = msg_of(&event) else {
            panic!("expected a block message");
        };
        assert_eq!(block.header.hash, BLOCK_HASH.to_vec());
        assert_eq!(block.header.nonce, 42);
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn low_data_strips_blocktxn_transaction_raw() {
        let mut event = message_event(Msg::Blocktxn(BlockTxn {
            block_hash: BLOCK_HASH.to_vec(),
            transactions: vec![transaction(), transaction()],
        }));

        strip_low_data(&mut event);

        let Msg::Blocktxn(blocktxn) = msg_of(&event) else {
            panic!("expected a blocktxn message");
        };
        assert_eq!(blocktxn.block_hash, BLOCK_HASH.to_vec());
        assert_eq!(blocktxn.transactions.len(), 2);
        for tx in &blocktxn.transactions {
            assert_eq!(tx.raw, None);
            assert_eq!(tx.txid, TXID.to_vec());
            assert_eq!(tx.wtxid, WTXID.to_vec());
        }
    }

    #[test]
    fn low_data_strips_compactblock_prefilled_transaction_raw() {
        let mut event = message_event(Msg::Compactblock(CompactBlock {
            header: block_header(),
            nonce: 7,
            short_ids: vec![vec![0xaa; 6]],
            transactions: vec![
                PrefilledTransaction {
                    diff_index: 0,
                    tx: transaction(),
                },
                PrefilledTransaction {
                    diff_index: 2,
                    tx: transaction_with_ids(TXID_2, WTXID_2, 0xee),
                },
            ],
        }));

        strip_low_data(&mut event);

        let Msg::Compactblock(compact_block) = msg_of(&event) else {
            panic!("expected a compactblock message");
        };
        assert_eq!(compact_block.nonce, 7);
        assert_eq!(compact_block.short_ids, vec![vec![0xaa; 6]]);
        assert_eq!(compact_block.header.hash, BLOCK_HASH.to_vec());
        assert_eq!(compact_block.transactions.len(), 2);
        assert_eq!(compact_block.transactions[0].diff_index, 0);
        assert_eq!(compact_block.transactions[0].tx.raw, None);
        assert_eq!(compact_block.transactions[0].tx.txid, TXID.to_vec());
        assert_eq!(compact_block.transactions[0].tx.wtxid, WTXID.to_vec());
        assert_eq!(compact_block.transactions[1].diff_index, 2);
        assert_eq!(compact_block.transactions[1].tx.raw, None);
        assert_eq!(compact_block.transactions[1].tx.txid, TXID_2.to_vec());
        assert_eq!(compact_block.transactions[1].tx.wtxid, WTXID_2.to_vec());
    }

    #[test]
    fn low_data_leaves_other_messages_untouched() {
        let mut event = message_event(Msg::Inv(Inv { items: vec![] }));
        let before = event.encode_to_vec();

        strip_low_data(&mut event);

        assert_eq!(event.encode_to_vec(), before);
    }

    #[test]
    fn low_data_leaves_non_p2p_events_untouched() {
        let mut event = Event::new(PeerObserverEvent::RpcExtractor(
            shared::protobuf::rpc_extractor::Rpc {
                rpc_event: Some(shared::protobuf::rpc_extractor::rpc::RpcEvent::Uptime(1234)),
            },
        ))
        .unwrap();
        let before = event.encode_to_vec();

        strip_low_data(&mut event);

        assert_eq!(event.encode_to_vec(), before);
    }
}
