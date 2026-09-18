# Event archives

Tooling to archive and replay peer-observer events.

## archiver

> archives peer-observer events to disk

A peer-observer tool that subscribes to a NATS server and persists events to binary files on disk.
By default, all event types are archived. Events can be filtered by type using flags, allowing
multiple archiver instances to run simultaneously for different recording jobs.

### File format

Events are stored as sequential length-delimited protobuf events from `protobuf/event.proto`,
preceded by a protobuf `ArchiveHeader` from `protobuf/archive/header.proto`. The
protobuf messages are encoded using `encode_length_delimited` from `prost`.

```
[ varint length ][ protobuf ArchiveHeader bytes ]
[ varint length ][ protobuf Event bytes ]
[ varint length ][ protobuf Event bytes ]
...
```

### Compression

Archive files are compressed with zstd using streaming compression — the writer is wrapped in a
`zstd::Encoder`, so files are written as `.bin.zst` directly. The default compression level is
22 (ultra). Use `--compression-level 3` for faster compression (~5x ratio)
or `--compression-level 0` to skip compression. Rotation (`--max-file-size`) is checked against
the compressed output stream. May overshoot slightly due to zstd internal buffering.

### Low-data mode

Raw transaction data makes up most of an archive. With `--low-data`, it is dropped before an
event is written. `tx`, `blocktxn`, and prefilled transactions in `cmpctblock` keep their txid and
wtxid. `block` messages keep only their header, including the block hash, and drop all block
transactions.

Everything else, including all connection, mempool and network metadata, is archived as usual. This
makes it feasible to collect data over longer periods, at the cost of no longer being able to
inspect the transactions and blocks themselves. Low-data mode requires `--messages`. It can be
combined with other event filters, which are archived unchanged.

Archives record the mode in their `ArchiveHeader`: `low_data` is `true` for low-data archives and
`false` for complete ones. Archives written before the field existed are treated as full-data.

### Address-relay and handshake modes

Two modes for dedicated recording jobs that only need a subset of the P2P messages:

- `--addr-relay` archives address-relay P2P messages: `getaddr`, `addr`, and `addrv2` (including
  addrv2 messages without any addresses in them).
- `--connections-with-handshakes` archives P2P connections with their version handshakes:
  `version` messages (both sent and received) and all P2P connection events. It's a superset of
  `--connections`.

Both modes are additive: they combine freely with each other and with the other event filters,
archiving the union of everything enabled. For example, a node recording both address relay and
connections with handshakes:

```
$ cargo run --bin archiver \
    --nats-address 127.0.0.1:4222 \
    --output-dir ./archive \
    --addr-relay --connections-with-handshakes
```

### Example

Archive all events from a NATS server, rotating files at 100 MB, with zstd compression:

```
$ cargo run --bin archiver -- \
    --nats-address 127.0.0.1:4222 \
    --output-dir ./archive \
    --base-name mainnet \
    --max-file-size 104857600 \
    --compression-level 22
```

Archive only P2P messages and mempool events:

```
$ cargo run --bin archiver \
    --nats-address 127.0.0.1:4222 \
    --output-dir ./archive \
    --messages --mempool
```

### Usage

```
Archive peer-observer events to disk

Usage: archiver [OPTIONS] --output-dir <OUTPUT_DIR>

Options:
  -a, --nats-address <ADDRESS>
          The NATS server address the extractor/tool should connect and subscribe to [default: 127.0.0.1:4222]
  -u, --nats-username <USERNAME>
          The NATS username the extractor/tool should try to authentificate to the NATS server with
  -p, --nats-password <PASSWORD>
          The NATS password the extractor/tool should try to authentificate to the NATS server with
  -f, --nats-password-file <PASSWORD_FILE>
          A path to a file containing a password the extractor/tool should try to authentificate to the NATS server with
  -o, --output-dir <OUTPUT_DIR>
          Output directory for archive files
  -b, --base-name <BASE_NAME>
          Base name for archive files (e.g., "mainnet" -> "mainnet.<timestamp>.bin.zst") [default: archive]
      --max-file-size <MAX_FILE_SIZE>
          Maximum compressed output size in bytes before rotation (default: 1GB) [default: 1073741824]
  -l, --log-level <LOG_LEVEL>
          The log level the tool should run on [default: INFO]
      --messages
          If passed, archive P2P message events
      --connections
          If passed, archive P2P connection events
      --mempool
          If passed, archive mempool events
      --validation
          If passed, archive validation events
      --rpc
          If passed, archive RPC events
      --p2p-extractor
          If passed, archive p2p-extractor events
      --log-extractor
          If passed, archive log-extractor events
      --ipc-extractor
          If passed, archive ipc-extractor events
      --compression-level <COMPRESSION_LEVEL>
              Zstd compression level (0 = no compression, 1-22). Default: 22 (ultra) [default: 22]
      --low-data
          If passed, don't archive raw transaction data. Requires --messages. Other enabled event filters are archived unchanged. Transactions keep their txid and wtxid. Blocks keep only their header
      --addr-relay
          If passed, archive address-relay P2P messages (getaddr, addr, addrv2, including empty addrv2). Additive: combines freely with the other event filters
      --connections-with-handshakes
          If passed, archive P2P connections with their version handshakes: version messages (both directions) and all P2P connection events. Additive: combines freely with the other event filters
  -h, --help
          Print help
  -V, --version
          Print version
```


## archiveinfo

Streams one or more peer-observer archives, or all archives directly inside a directory, and
reports which event categories and P2P message commands account for their uncompressed archive
bytes. Rows are sorted by size and include counts, byte totals, share, and average and maximum
event-frame sizes.

Supports `.bin` and `.bin.zst`. Directory discovery is non-recursive and ignores unsupported
filenames and nested directories. Each file gets a compact summary with its path, header,
on-disk size, event count, uncompressed size, and completion status. Full-data and low-data
archives then get separate summaries, each with its own totals, compression ratio, and tables.
Archives written before the `low_data` header field existed are treated as full-data archives.

On-disk size comes from filesystem metadata. Event sizes count the original uncompressed protobuf
bytes and length delimiters, including unknown protobuf fields. Each summary also reports header
bytes and the whole-file compression ratio. Zstd compresses a stream across event boundaries, so
exact compressed bytes cannot be attributed to individual events or categories. Byte sizes and
ratios are rounded for display; the exact uncompressed total is included in bytes.

The P2P table also reports original message payload bytes from `message.meta.size`, excluding
network framing. This is the message data size before low-data reduction, so low-data archives
can retain much less data than their payload totals.
Pass `--message-directions` to split rows into commands such as `block (received)` and `block (sent)`.
Direction is relative to the observed node, independent of the peer connection's `conn_type`.
Within each archive mode, category shares use all event bytes; P2P shares use all P2P event bytes,
including both directions.

Unrecognized P2P messages, including messages whose variant is missing or unknown to this build,
are grouped into an `unknown` row by default. Pass `--show-unknown-commands` to show their
individual command strings as `unknown "command"`. All displayed command strings are escaped
so control characters cannot affect the terminal. This also works with `--message-directions`.
Recognized commands such as `alert` and `reject` keep their own rows.

`archiveinfo` continues after read errors and exits with a non-zero status if any input failed.
Errors identify the path and, for event reads, the event number. Complete events preceding a
malformed or truncated event or zstd frame remain in the report, marked `status: partial`.
Compression ratios are unavailable for reports containing partially read archives. Inputs that
cannot be opened or whose headers cannot be read are excluded from totals; they still cause a
non-zero exit status, but do not make successfully read archives partial. Output is human-readable
only.

### Usage

```bash
cargo run -p archive --bin archiveinfo -- archive/test.0.bin.zst
cargo run -p archive --bin archiveinfo -- archive/full.bin.zst archive/low-data.bin.zst
cargo run -p archive --bin archiveinfo -- archive/
cargo run -p archive --bin archiveinfo -- --message-directions archive/
```

Pass multiple directories to compare full-data and low-data archives in one run:

```bash
cargo run -p archive --bin archiveinfo -- \
  archive/full-data/ archive/low-data/
```

You can also select individual files from different directories, for example:

```bash
cargo run -p archive --bin archiveinfo -- \
  archive/full-data/example.bin.zst \
  archive/low-data/example.bin.zst
```

Files and directories can be mixed. Each directory is scanned non-recursively, and summaries
are grouped by the archive header's `low_data` flag, regardless of directory names.

Set `-l` or `--log-level` to `error`, `warn`, `info` (the default), `debug`, or `trace`.
Values are case-insensitive; `off` is not supported. This controls log verbosity; the archive
report is still printed at every level.

```bash
cargo run -p archive --bin archiveinfo -- --log-level warn archive/full-data/ archive/low-data/
```

Run `cargo run -p archive --bin archiveinfo -- --help` for all options.

## replayer

Reads peer-observer archive files and logs decoded events at info level.

Supports:
- `.bin`
- `.bin.zst`

### Usage

```bash
  cargo run --bin replayer -- archive/test.0.bin
  cargo run --bin replayer -- archive/test.0.bin.zst
  cargo run --bin replayer -- archive/test.0.bin archive/test.1.bin.zst

```

### Example log output

```text
INFO [replayer] header: ArchiveHeader(created=1780140481)
INFO [replayer] [1] ts=1234567890 ebpf: ...
INFO [replayer] [2] ts=1234567891 ebpf: ...
INFO [replayer] total: 2 events
```

### Help

```
Read and display peer-observer archive files

Usage: replayer [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Archive files to read

Options:
  -l, --log-level <LOG_LEVEL>  The log level the tool should run on [default: INFO]
  -h, --help                   Print help
  -V, --version                Print version
```
