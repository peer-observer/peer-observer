# Event archives

Tooling to archive and replay peer-observer events.

## archiver

> archives peer-observer events to disk

A peer-observer tool that subscribes to a NATS server and persists events to binary files on disk.
By default, all event types are archived. Events can be filtered by type using flags, allowing
multiple archiver instances to run simultaneously for different recording jobs.

### File format

Events are stored as sequential length-delimited protobuf messages (using `encode_length_delimited`
from `prost`), preceded by a 16-byte header:

```
[ 2B magic "PA" ][ 1B version ][ 4B git commit hash ][ 9B reserved ]
[ varint length ][ protobuf Event bytes ]
[ varint length ][ protobuf Event bytes ]
...
```

The git commit hash in the header identifies the exact version of the protobuf definitions used
to record the file, allowing future readers to check out that commit if needed.

### Compression

Archive files are compressed with zstd using streaming compression — the writer is wrapped in a
`zstd::Encoder`, so files are written as `.bin.zst` directly. The default compression level is
22 (ultra). Use `--compression-level 3` for faster compression (~5x ratio)
or `--compression-level 0` to skip compression. Rotation (`--max-file-size`) is checked against
the compressed output stream. May overshoot slightly due to zstd internal buffering.

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
  -h, --help
          Print help
  -V, --version
          Print version
```


## replayer

Reads peer-observer archive files and prints decoded events to stdout.

Supports:
- `.bin`
- `.bin.zst`

### Usage

```bash
  cargo run --bin replayer -- archive/test.0.bin
  cargo run --bin replayer -- archive/test.0.bin.zst
  cargo run --bin replayer -- archive/test.0.bin archive/test.1.bin.zst
  
```

### Example output

```text
header: version=1 git=abcd1234
[1] ts=1234567890 ebpf: ...
[2] ts=1234567891 ebpf: ...
total: 2 events
```

### Help

```
Read and display peer-observer archive files

Usage: replayer <file.bin[.zst]> [file2.bin[.zst] ...]
```
