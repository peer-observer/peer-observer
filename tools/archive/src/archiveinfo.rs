use crate::read::ArchiveReader;
use shared::anyhow::{Context, Result};
use shared::clap::{self, Parser};
use shared::log;
use shared::protobuf::{
    archive::ArchiveHeader,
    ebpf_extractor::{
        ebpf::EbpfEvent,
        message::{message_event::Msg, MessageEvent},
    },
    event::{event::PeerObserverEvent, Event},
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use time::{macros::format_description, OffsetDateTime};

#[derive(Parser, Debug)]
#[command(version, about = "Inspect peer-observer archive files and directories")]
pub struct Args {
    /// Archive files or directories to inspect (directories are not recursive).
    #[arg(value_name = "PATH", required = true)]
    pub files: Vec<PathBuf>,

    /// Log level: error, warn, info, debug, or trace (case-insensitive).
    #[arg(short, long, default_value_t = log::Level::Info)]
    pub log_level: log::Level,

    /// Split P2P message rows into received and sent directions.
    #[arg(long)]
    pub message_directions: bool,

    /// Show escaped command strings for unknown P2P messages instead of one "unknown" row.
    #[arg(long)]
    pub show_unknown_commands: bool,
}

#[derive(Default)]
struct Counts {
    events: u64,
    bytes: u64,
    max: u64,
    payload_bytes: u64,
}

impl Counts {
    fn add_event(&mut self, bytes: u64, payload_bytes: u64) {
        self.events += 1;
        self.bytes += bytes;
        self.max = self.max.max(bytes);
        self.payload_bytes += payload_bytes;
    }

    fn merge(&mut self, other: Self) {
        self.events += other.events;
        self.bytes += other.bytes;
        self.max = self.max.max(other.max);
        self.payload_bytes += other.payload_bytes;
    }
}

// The same accumulator handles a single file and totals for one archive mode.
#[derive(Default)]
struct Stats {
    files: u64,
    partial_files: u64,
    file_bytes: u64,
    header_bytes: u64,
    protobuf_bytes: u64,
    delimiter_bytes: u64,
    events: Counts,
    time_range: Option<(u64, u64)>,
    categories: BTreeMap<&'static str, Counts>,
    messages: BTreeMap<(String, &'static str), Counts>,
}

impl Stats {
    fn include_time(&mut self, min: u64, max: u64) {
        self.time_range = Some(match self.time_range {
            Some((first, last)) => (first.min(min), last.max(max)),
            None => (min, max),
        });
    }

    fn add_file(&mut self, other: Self) {
        self.files += other.files;
        self.partial_files += other.partial_files;
        self.file_bytes += other.file_bytes;
        self.header_bytes += other.header_bytes;
        self.protobuf_bytes += other.protobuf_bytes;
        self.delimiter_bytes += other.delimiter_bytes;
        self.events.merge(other.events);
        if let Some((min, max)) = other.time_range {
            self.include_time(min, max);
        }
        for (key, counts) in other.categories {
            self.categories.entry(key).or_default().merge(counts);
        }
        for (key, counts) in other.messages {
            self.messages.entry(key).or_default().merge(counts);
        }
    }

    fn uncompressed(&self) -> u64 {
        self.header_bytes + self.events.bytes
    }

    fn status(&self) -> &'static str {
        if self.partial_files == 0 {
            "complete"
        } else {
            "partial"
        }
    }
}

fn classify(event: &Event) -> (&'static str, Option<&MessageEvent>) {
    match event.peer_observer_event.as_ref() {
        Some(PeerObserverEvent::EbpfExtractor(ebpf)) => match ebpf.ebpf_event.as_ref() {
            Some(EbpfEvent::Message(message)) => ("ebpf/message", Some(message)),
            Some(EbpfEvent::Connection(_)) => ("ebpf/connection", None),
            Some(EbpfEvent::Mempool(_)) => ("ebpf/mempool", None),
            Some(EbpfEvent::Validation(_)) => ("ebpf/validation", None),
            None => ("ebpf/unknown", None),
        },
        Some(PeerObserverEvent::RpcExtractor(_)) => ("rpc", None),
        Some(PeerObserverEvent::P2pExtractor(_)) => ("p2p-extractor", None),
        Some(PeerObserverEvent::LogExtractor(_)) => ("log", None),
        Some(PeerObserverEvent::IpcExtractor(_)) => ("ipc", None),
        None => ("unknown", None),
    }
}

fn inspect_file(
    path: &Path,
    directions: bool,
    show_unknown: bool,
) -> Result<(ArchiveHeader, Stats)> {
    let file_bytes = fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .len();
    let mut reader = ArchiveReader::open(path)
        .with_context(|| format!("reading archive header from {}", path.display()))?;
    let mut stats = Stats {
        files: 1,
        file_bytes,
        header_bytes: reader.header_size().framed_bytes() as u64,
        ..Stats::default()
    };
    while let Some(record) = reader.next_record() {
        let record = match record {
            Ok(record) => record,
            Err(error) => {
                log::error!(
                    "reading event {} from archive {}: {}",
                    stats.events.events + 1,
                    path.display(),
                    error
                );
                stats.partial_files = 1;
                break;
            }
        };
        let bytes = record.size.framed_bytes() as u64;
        stats.protobuf_bytes += record.size.protobuf_bytes as u64;
        stats.delimiter_bytes += record.size.delimiter_bytes as u64;
        stats.events.add_event(bytes, 0);
        stats.include_time(record.event.timestamp, record.event.timestamp);
        let (category, message) = classify(&record.event);
        stats
            .categories
            .entry(category)
            .or_default()
            .add_event(bytes, 0);
        if let Some(message) = message {
            let command = if matches!(message.msg, None | Some(Msg::Unknown(_))) {
                if show_unknown {
                    format!("unknown \"{}\"", message.meta.command.escape_default())
                } else {
                    "unknown".to_owned()
                }
            } else if message.meta.command.is_empty() {
                "<missing-command>".to_owned()
            } else {
                message.meta.command.escape_default().to_string()
            };
            let direction = match (directions, message.meta.inbound) {
                (false, _) => "",
                (true, true) => "received",
                (true, false) => "sent",
            };
            stats
                .messages
                .entry((command, direction))
                .or_default()
                .add_event(bytes, message.meta.size);
        }
    }
    Ok((reader.header, stats))
}

fn supported(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        name.ends_with(".bin") || name.ends_with(".bin.zst")
    })
}

fn resolve_inputs(inputs: &[PathBuf]) -> (BTreeMap<PathBuf, PathBuf>, bool) {
    // Deduplicate aliases while retaining the input extension used by ArchiveReader.
    let mut paths = BTreeMap::new();
    let mut failed = false;
    for input in inputs {
        let result = (|| -> Result<()> {
            let metadata = fs::metadata(input).context("reading input metadata")?;
            if metadata.is_file() {
                shared::anyhow::ensure!(supported(input), "expected a .bin or .bin.zst file");
                paths
                    .entry(fs::canonicalize(input).context("resolving archive path")?)
                    .or_insert_with(|| input.clone());
                return Ok(());
            }
            shared::anyhow::ensure!(metadata.is_dir(), "expected a file or directory");
            let entries = fs::read_dir(input).context("reading archive directory")?;
            let mut found = false;
            for entry in entries {
                let candidate = (|| -> Result<()> {
                    let path = entry.context("reading directory entry")?.path();
                    if supported(&path) {
                        let metadata = fs::metadata(&path)
                            .with_context(|| format!("reading metadata for {}", path.display()))?;
                        if metadata.is_file() {
                            found = true;
                            paths
                                .entry(fs::canonicalize(&path).with_context(|| {
                                    format!("resolving archive path {}", path.display())
                                })?)
                                .or_insert(path);
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = candidate {
                    log::error!("{}: {error:#}", input.display());
                    failed = true;
                }
            }
            shared::anyhow::ensure!(found, "no .bin or .bin.zst archive files found");
            Ok(())
        })();
        if let Err(error) = result {
            log::error!("{}: {error:#}", input.display());
            failed = true;
        }
    }
    (paths, failed)
}

/// Streams the inputs and writes a report. Returns true if any input failed.
pub fn run(args: &Args, out: &mut impl Write) -> Result<bool> {
    let (paths, mut failed) = resolve_inputs(&args.files);
    let mut totals: BTreeMap<bool, Stats> = BTreeMap::new();
    for path in paths.into_values() {
        match inspect_file(&path, args.message_directions, args.show_unknown_commands) {
            Ok((header, stats)) => {
                writeln!(out, "Archive: {}", path.display())?;
                let compression = if path.extension().is_some_and(|ext| ext == "zst") {
                    "zstd"
                } else {
                    "none"
                };
                writeln!(
                    out,
                    "  created: {}  low_data: {}  compression: {}",
                    format_timestamp(i128::from(header.created) * 1000),
                    header.is_low_data(),
                    compression
                )?;
                writeln!(
                    out,
                    "  events: {}  on disk: {}  uncompressed: {}  status: {}\n",
                    stats.events.events,
                    human_bytes(stats.file_bytes),
                    human_bytes(stats.uncompressed()),
                    stats.status()
                )?;
                failed |= stats.partial_files != 0;
                totals
                    .entry(header.is_low_data())
                    .or_default()
                    .add_file(stats);
            }
            Err(error) => {
                log::error!("{error:#}");
                failed = true;
            }
        }
    }
    for (low_data, stats) in totals {
        render_summary(out, &stats, low_data, args.message_directions)?;
    }
    Ok(failed)
}

fn render_summary(
    out: &mut impl Write,
    stats: &Stats,
    low_data: bool,
    directions: bool,
) -> io::Result<()> {
    let partial = stats.partial_files > 0;
    writeln!(
        out,
        "{}",
        if low_data {
            "Low-data summary"
        } else {
            "Full-data summary"
        }
    )?;
    writeln!(out, "  files: {}  status: {}", stats.files, stats.status())?;
    writeln!(out, "  events: {}", stats.events.events)?;
    writeln!(
        out,
        "  on disk: {} ({} bytes)",
        human_bytes(stats.file_bytes),
        stats.file_bytes
    )?;
    writeln!(out, "  header frames: {} B", stats.header_bytes)?;
    writeln!(out, "  event protobuf: {} B", stats.protobuf_bytes)?;
    writeln!(out, "  event delimiters: {} B", stats.delimiter_bytes)?;
    writeln!(
        out,
        "  uncompressed: {} ({} bytes)",
        human_bytes(stats.uncompressed()),
        stats.uncompressed()
    )?;
    if partial {
        writeln!(out, "  compression ratio: unavailable (partial archive)")?;
    } else {
        writeln!(
            out,
            "  compression ratio: {:.2}x",
            stats.uncompressed() as f64 / stats.file_bytes.max(1) as f64
        )?;
    }
    if let Some((min, max)) = stats.time_range {
        writeln!(
            out,
            "  event time range: {} .. {} ({:.2} hours)",
            format_timestamp(i128::from(min)),
            format_timestamp(i128::from(max)),
            (max - min) as f64 / 3_600_000.0
        )?;
    }
    writeln!(out, "  Sizes below are uncompressed Event frames, including length delimiters. Zstd size is measured only per file.")?;
    if partial {
        writeln!(
            out,
            "  Partial report: only successfully decoded events are included; see read errors."
        )?;
    }

    render_table(
        out,
        "Event categories",
        stats
            .categories
            .iter()
            .map(|(name, counts)| ((*name).to_owned(), counts))
            .collect(),
        stats.events.bytes,
        false,
    )?;
    if !stats.messages.is_empty() {
        let rows = stats
            .messages
            .iter()
            .map(|((command, direction), counts)| {
                let label = if direction.is_empty() {
                    command.clone()
                } else {
                    format!("{command} ({direction})")
                };
                (label, counts)
            })
            .collect();
        render_table(
            out,
            "P2P messages",
            rows,
            stats.messages.values().map(|counts| counts.bytes).sum(),
            true,
        )?;
        writeln!(out, "  P2P payload is the original message data size before low-data reduction; excludes network framing.")?;
        if directions {
            writeln!(out, "  Received/sent is message flow relative to this node, independent of connection direction.")?;
        }
    }
    writeln!(out)
}

fn render_table(
    out: &mut impl Write,
    title: &str,
    mut rows: Vec<(String, &Counts)>,
    parent: u64,
    show_payload: bool,
) -> io::Result<()> {
    rows.sort_by(|(a_name, a), (b_name, b)| b.bytes.cmp(&a.bytes).then_with(|| a_name.cmp(b_name)));
    writeln!(out, "\n{title}")?;
    write!(
        out,
        "  {:<26} {:>10} {:>13} {:>7} {:>12} {:>12}",
        "name", "events", "event bytes", "share", "avg", "max"
    )?;
    writeln!(out, "{}", if show_payload { "    P2P payload" } else { "" })?;
    for (name, counts) in rows {
        let avg = counts.bytes as f64 / counts.events.max(1) as f64;
        let avg = if avg < 1024.0 {
            format!("{avg:.1} B")
        } else {
            human_bytes(avg.round() as u64)
        };
        write!(
            out,
            "  {:<26} {:>10} {:>13} {:>6.1}% {:>12} {:>12}",
            name,
            counts.events,
            human_bytes(counts.bytes),
            100.0 * counts.bytes as f64 / parent.max(1) as f64,
            avg,
            human_bytes(counts.max)
        )?;
        if show_payload {
            write!(out, " {:>14}", human_bytes(counts.payload_bytes))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn format_timestamp(milliseconds: i128) -> String {
    i64::try_from(milliseconds.div_euclid(1000))
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|date| {
            date.format(format_description!(
                "[year]-[month]-[day] [hour]:[minute]:[second] UTC"
            ))
            .ok()
        })
        .unwrap_or_else(|| format!("{milliseconds} ms (out of range)"))
}

fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", units[unit])
}
