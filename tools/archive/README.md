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
  -h, --help
          Print help
  -V, --version
          Print version
```


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
