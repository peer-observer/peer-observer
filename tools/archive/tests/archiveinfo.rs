use archive::archiveinfo::{self, Args};
use shared::{
    log,
    prost::Message,
    protobuf::{
        archive::ArchiveHeader,
        bitcoin_primitives::Transaction,
        ebpf_extractor::{
            ebpf,
            message::{message_event::Msg, Block, MessageEvent, Metadata, Tx, Unknown},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
        rpc_extractor::{self, rpc},
    },
    zstd,
};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("archiveinfo-{}-{nonce}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        let bytes = if name.ends_with(".zst") {
            zstd::encode_all(bytes, 1).unwrap()
        } else {
            bytes.to_vec()
        };
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn archive_bytes(low_data: Option<bool>, events: &[Event]) -> Vec<u8> {
    let mut bytes = ArchiveHeader {
        created: 1,
        low_data,
    }
    .encode_length_delimited_to_vec();
    for event in events {
        bytes.extend(event.encode_length_delimited_to_vec());
    }
    bytes
}

fn rpc_event(timestamp: u64) -> Event {
    Event {
        timestamp,
        peer_observer_event: Some(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
            rpc_event: Some(rpc::RpcEvent::Uptime(12345)),
        })),
    }
}

fn transaction(raw_len: Option<usize>) -> Transaction {
    Transaction {
        txid: vec![1; 32],
        wtxid: vec![2; 32],
        raw: raw_len.map(|len| vec![3; len]),
    }
}

fn message(command: &str, inbound: bool, payload_bytes: u64, msg: Msg) -> Event {
    Event {
        timestamp: 1000,
        peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                meta: Metadata {
                    command: command.into(),
                    inbound,
                    size: payload_bytes,
                    conn_type: 1,
                    ..Default::default()
                },
                msg: Some(msg),
            })),
        })),
    }
}

fn block(inbound: bool, payload_bytes: u64, raw_len: Option<usize>) -> Event {
    message(
        "block",
        inbound,
        payload_bytes,
        Msg::Block(Block {
            header: Default::default(),
            transactions: raw_len
                .map(|len| transaction(Some(len)))
                .into_iter()
                .collect(),
        }),
    )
}

fn report(paths: &[PathBuf], directions: bool) -> (bool, String) {
    report_with_unknown_commands(paths, directions, false)
}

fn report_with_unknown_commands(
    paths: &[PathBuf],
    directions: bool,
    show_unknown_commands: bool,
) -> (bool, String) {
    let mut output = Vec::new();
    let failed = archiveinfo::run(
        &Args {
            files: paths.to_vec(),
            log_level: log::Level::Info,
            message_directions: directions,
            show_unknown_commands,
        },
        &mut output,
    )
    .unwrap();
    (failed, String::from_utf8(output).unwrap())
}

fn normalized(output: &str) -> String {
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn frame_bytes(events: &[Event]) -> usize {
    events
        .iter()
        .map(|event| event.encode_length_delimited_to_vec().len())
        .sum()
}

fn assert_row(
    output: &str,
    label: &str,
    events: &[Event],
    total: usize,
    payload_bytes: Option<u64>,
) {
    let bytes = frame_bytes(events);
    let max = events
        .iter()
        .map(|event| event.encode_length_delimited_to_vec().len())
        .max()
        .unwrap();
    let expected = format!(
        "{label} {} {bytes} B {:.1}% {:.1} B {max} B{}",
        events.len(),
        bytes as f64 * 100.0 / total as f64,
        bytes as f64 / events.len() as f64,
        payload_bytes
            .map(|bytes| format!(" {bytes} B"))
            .unwrap_or_default()
    );
    assert!(
        output.lines().any(|line| normalized(line) == expected),
        "missing row {expected}:\n{output}"
    );
}

fn cli(paths: &[&Path]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_archiveinfo"))
        .args(paths)
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn reports_exact_counts_frame_sizes_and_old_header() {
    let dir = TestDir::new();
    let blocks = [block(true, 100, Some(10)), block(false, 200, Some(40))];
    let events = [blocks[0].clone(), rpc_event(10), blocks[1].clone()];
    let bytes = archive_bytes(None, &events);
    let path = dir.write("old.bin", &bytes);
    let (failed, output) = report(std::slice::from_ref(&path), false);
    assert!(!failed);
    let flat = normalized(&output);
    assert!(flat.contains(&format!("Archive: {}", path.display())));
    assert!(flat.contains("created: 1970-01-01 00:00:01 UTC low_data: false compression: none"));
    assert!(flat.contains(&format!("uncompressed: {} B", bytes.len())));
    assert!(flat.contains(&format!("on disk: {} B", bytes.len())));
    assert!(flat.contains("events: 3"));
    assert!(flat.contains("status: complete"));
    assert_row(&output, "ebpf/message", &blocks, frame_bytes(&events), None);
    assert_row(&output, "rpc", &events[1..2], frame_bytes(&events), None);
    assert_row(&output, "block", &blocks, frame_bytes(&blocks), Some(300));
    let categories = output.split("Event categories").nth(1).unwrap();
    assert!(categories.find("ebpf/message").unwrap() < categories.find("rpc").unwrap());
}

#[test]
fn directions_split_and_merge_counts_and_payload_bytes() {
    let dir = TestDir::new();
    let blocks = [
        block(true, 100, Some(10)),
        block(false, 200, None),
        block(false, 300, Some(20)),
    ];
    let tx = message(
        "tx",
        true,
        80,
        Msg::Tx(Tx {
            tx: transaction(None),
        }),
    );
    let paths = [
        dir.write("first.bin", &archive_bytes(None, &blocks[..2])),
        dir.write(
            "second.bin.zst",
            &archive_bytes(Some(false), &[blocks[2].clone(), tx.clone()]),
        ),
    ];
    let total = frame_bytes(&blocks) + frame_bytes(std::slice::from_ref(&tx));
    let (failed, output) = report(&paths, false);
    assert!(!failed);
    assert_row(&output, "block", &blocks, total, Some(600));
    assert!(!output.contains("(received)"));
    assert!(!output.contains("(sent)"));
    let summary = normalized(output.split("Full-data summary").nth(1).unwrap());
    assert!(summary.contains("files: 2 status: complete"));
    assert!(summary.contains("events: 4"));
    assert_eq!(output.matches("P2P messages").count(), 1);

    let (failed, output) = report(&paths, true);
    assert!(!failed);
    assert_row(&output, "block (received)", &blocks[..1], total, Some(100));
    assert_row(&output, "block (sent)", &blocks[1..], total, Some(500));
    assert_row(&output, "tx (received)", &[tx], total, Some(80));
    assert!(!output.contains("tx (sent)"));
    assert_eq!(output.matches("P2P messages").count(), 1);
}

#[test]
fn full_and_low_data_archives_have_separate_summaries() {
    let dir = TestDir::new();
    let mut paths = Vec::new();
    let mut sizes = Vec::new();
    let mut archive_sizes = Vec::new();
    let mut mode_events = Vec::new();
    for low_data in [false, true] {
        let raw = (!low_data).then_some(30);
        let events = [
            block(true, 200, raw),
            message(
                "tx",
                true,
                100,
                Msg::Tx(Tx {
                    tx: transaction(raw),
                }),
            ),
        ];
        let bytes = archive_bytes(Some(low_data), &events);
        let path = dir.write(&format!("mode-{low_data}.bin.zst"), &bytes);
        let (failed, output) = report(std::slice::from_ref(&path), false);
        assert!(!failed);
        assert!(normalized(&output).contains(&format!("low_data: {low_data} compression: zstd")));
        assert!(normalized(&output).contains(&format!("uncompressed: {} B", bytes.len())));
        assert_row(
            &output,
            "block",
            &events[..1],
            frame_bytes(&events),
            Some(200),
        );
        assert_row(&output, "tx", &events[1..], frame_bytes(&events), Some(100));
        sizes.push(frame_bytes(&events));
        archive_sizes.push(bytes.len());
        mode_events.push(events);
        paths.push(path);
    }
    assert!(sizes[0] > sizes[1]);
    let (failed, output) = report(&paths, false);
    assert!(!failed);
    let (full, low) = output.split_once("Low-data summary").unwrap();
    let full = full.split_once("Full-data summary").unwrap().1;
    for (index, summary) in [full, low].into_iter().enumerate() {
        let flat = normalized(summary);
        assert!(flat.contains("files: 1 status: complete"), "{output}");
        assert!(flat.contains("events: 2"), "{output}");
        assert!(
            flat.contains(&format!("uncompressed: {} B", archive_sizes[index])),
            "{output}"
        );
        let file_bytes = fs::metadata(&paths[index]).unwrap().len();
        assert!(
            flat.contains(&format!("on disk: {file_bytes} B")),
            "{output}"
        );
        assert!(
            flat.contains(&format!(
                "compression ratio: {:.2}x",
                archive_sizes[index] as f64 / file_bytes as f64
            )),
            "{output}"
        );
        let events = &mode_events[index];
        assert_row(summary, "ebpf/message", events, sizes[index], None);
        assert_row(summary, "block", &events[..1], sizes[index], Some(200));
        assert_row(summary, "tx", &events[1..], sizes[index], Some(100));
    }
    assert!(!output.contains("low_data: mixed"));
    assert_eq!(output.matches("Event categories").count(), 2);
    assert_eq!(output.matches("P2P messages").count(), 2);
}

#[test]
fn partial_low_data_archive_does_not_taint_full_data_summary() {
    let dir = TestDir::new();
    let full_bytes = archive_bytes(Some(false), &[rpc_event(1000)]);
    let full = dir.write("full.bin.zst", &full_bytes);
    let mut low_bytes = archive_bytes(Some(true), &[rpc_event(2000)]);
    low_bytes.extend([4, 0x08]);
    let low = dir.write("low.bin.zst", &low_bytes);
    let (code, output) = cli(&[&full, &low]);
    assert_eq!(code, 1, "{output}");
    let (full_summary, low_summary) = output.split_once("Low-data summary").unwrap();
    let full_summary = normalized(full_summary.split_once("Full-data summary").unwrap().1);
    let low_summary = normalized(low_summary);
    assert!(
        full_summary.contains("files: 1 status: complete"),
        "{output}"
    );
    assert!(full_summary.contains("events: 1"), "{output}");
    assert!(
        full_summary.contains(&format!(
            "compression ratio: {:.2}x",
            full_bytes.len() as f64 / fs::metadata(full).unwrap().len() as f64
        )),
        "{output}"
    );
    assert!(!full_summary.contains("partial"), "{output}");
    assert!(low_summary.contains("files: 1 status: partial"), "{output}");
    assert!(low_summary.contains("events: 1"), "{output}");
    assert!(
        low_summary.contains("compression ratio: unavailable (partial archive)"),
        "{output}"
    );
}

#[test]
fn directory_discovery_ignores_other_files_and_nested_directories() {
    let dir = TestDir::new();
    dir.write("first.bin", &archive_bytes(None, &[rpc_event(1)]));
    dir.write(
        "second.bin.zst",
        &archive_bytes(Some(false), &[rpc_event(2), rpc_event(3)]),
    );
    dir.write("notes.txt", b"ignored");
    dir.write("archive.bin.zst.bak", b"ignored");
    fs::create_dir(dir.0.join("nested.bin")).unwrap();
    dir.write(
        "nested.bin/hidden.bin",
        &archive_bytes(None, &[rpc_event(4)]),
    );
    let (failed, output) = report(
        &[
            dir.0.clone(),
            dir.0.join("first.bin"),
            dir.0.join("./first.bin"),
        ],
        false,
    );
    assert!(!failed);
    assert!(output.contains("first.bin"));
    assert!(output.contains("second.bin.zst"));
    for ignored in [
        "notes.txt",
        "archive.bin.zst.bak",
        "nested.bin",
        "hidden.bin",
    ] {
        assert!(!output.contains(ignored));
    }
    assert!(normalized(&output).contains("files: 2 status: complete"));
    assert!(normalized(&output).contains("events: 3"));
    assert_eq!(output.matches("Event categories").count(), 1);
}

#[test]
fn bad_headers_and_event_frames_have_context_and_do_not_stop_later_files() {
    let dir = TestDir::new();
    let good_bytes = archive_bytes(None, &[rpc_event(1000)]);
    let good = dir.write("good.bin.zst", &good_bytes);
    let good_file_bytes = fs::metadata(&good).unwrap().len();
    let good_ratio = format!(
        "compression ratio: {:.2}x",
        good_bytes.len() as f64 / good_file_bytes as f64
    );
    for extension in ["bin", "bin.zst"] {
        for (name, tail) in [("malformed", &[1, 0xff][..]), ("truncated", &[4, 0x08][..])] {
            let mut bytes = archive_bytes(None, &[rpc_event(1000)]);
            bytes.extend(tail);
            let bad = dir.write(&format!("{name}.{extension}"), &bytes);
            let (code, output) = cli(&[&bad, &good]);
            assert_eq!(code, 1, "{output}");
            assert!(output.contains(&bad.display().to_string()));
            assert!(output.contains("event 2"));
            assert!(output.contains(&good.display().to_string()));
            let summary = normalized(output.split("Full-data summary").nth(1).unwrap());
            assert!(summary.contains("events: 2"), "{output}");
            assert!(summary.contains("status: partial"));
            assert!(summary.contains("compression ratio: unavailable"));
        }
        for bytes in [&[][..], &[1, 0xff][..], &[2, 0x08][..]] {
            let bad = dir.write(&format!("header.{extension}"), bytes);
            let (code, output) = cli(&[&bad, &good]);
            assert_eq!(code, 1, "{output}");
            assert!(output.contains(&bad.display().to_string()));
            assert!(output.contains("archive header"));
            assert!(output.contains(&good.display().to_string()));
            let summary = normalized(output.split("Full-data summary").nth(1).unwrap());
            assert!(summary.contains("events: 1"), "{output}");
            assert!(summary.contains("status: complete"), "{output}");
            assert!(summary.contains(&good_ratio), "{output}");
            assert!(
                summary.contains(&format!("uncompressed: {} B", good_bytes.len())),
                "{output}"
            );
            assert!(
                summary.contains(&format!("on disk: {good_file_bytes} B")),
                "{output}"
            );
            assert!(!summary.contains("partial"), "{output}");
        }
    }
}

#[test]
fn input_resolution_errors_preserve_complete_archive_summary_and_ratio() {
    let dir = TestDir::new();
    let good_bytes = archive_bytes(None, &[rpc_event(1000)]);
    let good = dir.write("good.bin.zst", &good_bytes);
    let good_file_bytes = fs::metadata(&good).unwrap().len();
    let good_ratio = format!(
        "compression ratio: {:.2}x",
        good_bytes.len() as f64 / good_file_bytes as f64
    );
    let empty_dir = dir.0.join("empty");
    fs::create_dir(&empty_dir).unwrap();
    let unsupported = dir.write("unsupported.txt", b"not an archive");
    for bad in [dir.0.join("missing.bin"), unsupported, empty_dir] {
        let (code, output) = cli(&[&bad, &good]);
        assert_eq!(code, 1, "{output}");
        assert!(output.contains(&bad.display().to_string()), "{output}");
        let summary = normalized(output.split("Full-data summary").nth(1).unwrap());
        assert!(summary.contains("files: 1"), "{output}");
        assert!(summary.contains("events: 1"), "{output}");
        assert!(summary.contains("status: complete"), "{output}");
        assert!(summary.contains(&good_ratio), "{output}");
        assert!(
            summary.contains(&format!("uncompressed: {} B", good_bytes.len())),
            "{output}"
        );
        assert!(
            summary.contains(&format!("on disk: {good_file_bytes} B")),
            "{output}"
        );
        assert!(!summary.contains("partial"), "{output}");
    }
}

#[test]
fn unknown_commands_are_grouped_or_revealed_safely_with_directions() {
    let dir = TestDir::new();
    let mut future = message("future", true, 13, Msg::Unknown(Unknown::default()));
    let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &mut future.peer_observer_event else {
        unreachable!()
    };
    let Some(ebpf::EbpfEvent::Message(message_event)) = &mut ebpf.ebpf_event else {
        unreachable!()
    };
    message_event.msg = None;
    let events = [
        message(
            "goodbye",
            true,
            3,
            Msg::Unknown(Unknown {
                command: "goodbye".into(),
                payload: vec![0; 3],
            }),
        ),
        message(
            "bad\u{7}cmd",
            false,
            9,
            Msg::Unknown(Unknown {
                command: "bad\u{7}cmd".into(),
                payload: vec![0; 9],
            }),
        ),
        future,
    ];
    let paths = [
        dir.write("unknown.bin", &archive_bytes(None, &events[..2])),
        dir.write("newer.bin.zst", &archive_bytes(None, &events[2..])),
    ];
    let total = frame_bytes(&events);
    for directions in [false, true] {
        let (failed, output) = report(&paths, directions);
        assert!(!failed);
        for hidden in ["goodbye", "bad", "future", "\u{7}"] {
            assert!(!output.contains(hidden), "{output}");
        }
        if directions {
            assert_row(
                &output,
                "unknown (received)",
                &[events[0].clone(), events[2].clone()],
                total,
                Some(16),
            );
            assert_row(&output, "unknown (sent)", &events[1..2], total, Some(9));
        } else {
            assert_row(&output, "unknown", &events, total, Some(25));
        }

        let (failed, output) = report_with_unknown_commands(&paths, directions, true);
        assert!(!failed);
        assert!(!output.contains('\u{7}'), "{output}");
        for (index, (label, direction, payload)) in [
            (r#"unknown "goodbye""#, "received", 3),
            (r#"unknown "bad\u{7}cmd""#, "sent", 9),
            (r#"unknown "future""#, "received", 13),
        ]
        .into_iter()
        .enumerate()
        {
            let label = if directions {
                format!("{label} ({direction})")
            } else {
                label.to_owned()
            };
            assert_row(
                &output,
                &label,
                &events[index..index + 1],
                total,
                Some(payload),
            );
        }
    }
}

#[test]
fn recognized_commands_keep_their_rows_and_escape_terminal_characters() {
    let dir = TestDir::new();
    let events = [
        message("alert", true, 1, Msg::Alert(Default::default())),
        message("reject", true, 2, Msg::Reject(Default::default())),
        message("ping\x1b[31m\n\"\\", true, 8, Msg::Ping(Default::default())),
    ];
    let path = dir.write("known.bin", &archive_bytes(None, &events));
    for show_unknown in [false, true] {
        let (failed, output) =
            report_with_unknown_commands(std::slice::from_ref(&path), false, show_unknown);
        assert!(!failed);
        assert!(!output.contains('\x1b'), "{output}");
        assert_row(
            &output,
            "alert",
            &events[..1],
            frame_bytes(&events),
            Some(1),
        );
        assert_row(
            &output,
            "reject",
            &events[1..2],
            frame_bytes(&events),
            Some(2),
        );
        assert_row(
            &output,
            r#"ping\u{1b}[31m\n\"\\"#,
            &events[2..],
            frame_bytes(&events),
            Some(8),
        );
    }
}

#[test]
fn messages_without_commands_keep_their_counts_and_payload_bytes() {
    let dir = TestDir::new();
    let events = [message(
        "",
        true,
        80,
        Msg::Tx(Tx {
            tx: transaction(None),
        }),
    )];
    let path = dir.write("missing-command.bin", &archive_bytes(None, &events));
    for (directions, label) in [
        (false, "<missing-command>"),
        (true, "<missing-command> (received)"),
    ] {
        let (failed, output) = report(std::slice::from_ref(&path), directions);
        assert!(!failed);
        assert_row(&output, label, &events, frame_bytes(&events), Some(80));
    }
}

#[test]
fn event_time_range_uses_minimum_and_maximum_millisecond_timestamps() {
    let dir = TestDir::new();
    let path = dir.write(
        "unordered.bin",
        &archive_bytes(
            None,
            &[rpc_event(86_401_234), rpc_event(1_234), rpc_event(30_000)],
        ),
    );
    let (failed, output) = report(&[path], false);
    assert!(!failed);
    assert!(
        normalized(&output).contains(
            "event time range: 1970-01-01 00:00:01 UTC .. 1970-01-02 00:00:01 UTC (24.00 hours)"
        ),
        "{output}"
    );
}

#[test]
fn out_of_range_header_and_event_timestamps_remain_readable() {
    let dir = TestDir::new();
    let mut bytes = ArchiveHeader {
        created: u64::MAX,
        low_data: None,
    }
    .encode_length_delimited_to_vec();
    rpc_event(u64::MAX)
        .encode_length_delimited(&mut bytes)
        .unwrap();
    let path = dir.write("out-of-range.bin", &bytes);
    let (failed, output) = report(&[path], false);
    assert!(!failed);
    assert!(
        normalized(&output).contains(&format!(
            "created: {} ms (out of range) low_data: false",
            i128::from(u64::MAX) * 1000
        )),
        "{output}"
    );
    assert!(
        normalized(&output).contains(&format!(
            "event time range: {} ms (out of range) .. {} ms (out of range) (0.00 hours)",
            u64::MAX,
            u64::MAX
        )),
        "{output}"
    );
}

#[test]
fn unfinished_zstd_frame_keeps_complete_events_and_returns_failure() {
    let dir = TestDir::new();
    let mut encoder = zstd::Encoder::new(Vec::new(), 1).unwrap();
    encoder.include_checksum(true).unwrap();
    encoder
        .write_all(&archive_bytes(None, &[rpc_event(1000)]))
        .unwrap();
    encoder.flush().unwrap();
    let mut bytes = encoder.finish().unwrap();
    bytes.pop();
    let path = dir.0.join("unfinished.bin.zst");
    fs::write(&path, bytes).unwrap();
    let (code, output) = cli(&[&path]);
    assert_eq!(code, 1, "{output}");
    assert!(output.contains(&path.display().to_string()));
    assert!(output.contains("event 2"));
    assert!(normalized(&output).contains("events: 1"));
    assert!(normalized(&output).contains("status: partial"));
    assert!(normalized(&output).contains("compression ratio: unavailable"));
}

#[test]
fn empty_archive_is_valid_but_empty_directory_and_missing_paths_fail() {
    let dir = TestDir::new();
    let missing = dir.0.join("missing.bin");
    assert_eq!(cli(&[&missing]).0, 1);
    assert_eq!(cli(&[&dir.0]).0, 1);
    let empty = dir.write("empty.bin", &archive_bytes(None, &[]));
    let (failed, output) = report(&[empty], false);
    assert!(!failed);
    assert!(normalized(&output).contains("events: 0"));
    assert!(!output.contains("NaN"));
}
