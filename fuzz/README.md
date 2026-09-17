# Fuzzing

Coverage-guided fuzz targets for the places where peer-observer parses data it
does not control. Built with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
and libFuzzer. The crate is its own workspace and is not built by
`cargo build` in the repository root.

## Targets

| Target             | Input                                              | Exercises                                                                                 |
|--------------------|----------------------------------------------------|-------------------------------------------------------------------------------------------|
| `ebpf_p2p_message` | A P2P message ring buffer entry (metadata + payload) | `P2PMessage::from_bytes`, rust-bitcoin decode, protobuf conversion, Display, JSON       |
| `ebpf_ringbuffer`  | A kind byte plus a connection/mempool/validation struct | The other `from_bytes` readers and their protobuf conversions                        |
| `p2p_read_message` | Bytes as sent by a remote peer over the socket     | `p2p_extractor::read_and_decode_message` and the protobuf conversion                     |
| `archive_reader`   | An uncompressed archive file                       | `ArchiveReader` framing, header, event decode, Display                                   |
| `event_decode`     | One protobuf-encoded `Event`                       | What every NATS consumer does with a received event: Display, JSON, re-encode           |
| `log_line`         | One debug.log line                                 | `log_matchers::parse_log_event` and the log event Display / JSON                         |
| `metrics_events`   | A sequence of length-delimited `Event`s            | The metrics tool's event handlers and the state they keep between events              |

The `ebpf_*` targets only generate inputs that respect the invariants the BPF
program guarantees (see `src/lib.rs`), e.g. that `bool` fields hold 0 or 1.

## Running

`cargo-fuzz` is part of `shell.nix`. The targets build on the stable toolchain
when the sanitizer is disabled with `-s none`; AddressSanitizer needs a nightly
toolchain but adds little here since the code under test is almost entirely
safe Rust.

```sh
cd fuzz
# Generate the seed corpora once (see below).
cargo run --example gen_seeds

# Run one target. The seeds/ directory is used as the starting corpus and new
# inputs are written to corpus/<target>/, which has to exist.
mkdir -p corpus/ebpf_p2p_message
cargo fuzz run -s none ebpf_p2p_message corpus/ebpf_p2p_message seeds/ebpf_p2p_message

# Time-limited run, e.g. for CI.
mkdir -p corpus/archive_reader
cargo fuzz run -s none archive_reader corpus/archive_reader seeds/archive_reader -- -max_total_time=600

# List targets, build all of them.
cargo fuzz list
cargo fuzz build -s none
```

Crashing inputs are written to `artifacts/<target>/`. Reproduce and minimize with:

```sh
cargo fuzz run -s none <target> artifacts/<target>/crash-...
cargo fuzz tmin -s none <target> artifacts/<target>/crash-...
```

Once a crash is fixed, add the minimized input as a regular unit test in the
crate that owned the bug so it stays covered without the fuzzer.

## Seeds

`seeds/<target>/` holds small valid inputs generated from real encodings by
`examples/gen_seeds.rs`. They are not committed: generate them with

```sh
cargo run --example gen_seeds
```

before fuzzing, and regenerate them after changing the protobuf schema, the
archive format, or the ring buffer structs. The generator is the place to add
new seeds.
