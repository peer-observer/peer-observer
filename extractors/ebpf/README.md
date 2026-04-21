# `epbf` extractor

> publishes events extracted via eBPF tracepoints

A peer-observer extractor that hooks into the Bitcoin Core tracepoint interface
and publishes the events into a NATS pub-sub queue.

This extractor is Linux only since eBPF is a Linux kernel feature.

Only Bitcoin Core v29.0 or newer is supported. Bitcoin Core needs to be build
with `-DWITH_USDT=true` for the tracepoints to be compiled in. By default,
the official release binaries contain tracepoints. See the [Listing available
tracepoints](https://github.com/bitcoin/bitcoin/blob/master/doc/tracing.md#listing-available-tracepoints)
section to find out which tracepoints your binary supports.

The extractor currently hooks into the following Bitcoin Core tracepoints by default. To turn off some
tracepoint categories, see the ebpf-extractor [usage](#Usage) section below.
- `net:inbound_message`
- `net:outbound_message`
- `net:inbound_connection`
- `net:outbound_connection`
- `net:closed_connection`
- `net:evicted_inbound_connection`
- `net:misbehaving_connection`
- `validation:block_connected`
- `mempool:added`
- `mempool:removed`
- `mempool:rejected`
- `mempool:replaced`
- `validation:block_connected`

To hook into the tracepoints, the extractor needs the path to the `bitcoind` binary and
the PID of the process. If the `bitcoind` process is stopped or restarted, the extractor
needs to be restarted too.

Loading the eBPF tracing code into the Linux kernel requires priviledges. While a quick
and dirty way is to run the ebpf-extractor with `sudo` (or under `root`), this is not
recommended. Ideally, the ebpf-extractor runs in a VM alongside a Bitcoin node. The
ebpf-extractor requires the `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` Linux
capabilities. A NixOS definition of a systemd service running the ebpf-extractor as
a non-root user can be found in this [NixOS module](https://github.com/0xB10C/nix/blob/master/modules/peer-observer/default.nix)
(look for `systemd.services.peer-observer-ebpf-extractor`).


## NATS settings

Since the eBPF extractor processes, for example, P2P messages, the events
published to NATS can be as large as a large P2P message (e.g. a `block`
message). Since NATS has a [1 MB default message](https://docs.nats.io/running-a-nats-service/configuration#limits) size, increasing the
NATS setting `max_payload` to `5242880` (5 MB) is required. Otherwise, the
following error might occur:

```log
Maximum Payload Violation on connection [12]
ERROR [extractor] could not publish message in 'handle_net_message': Connection reset by peer (os error 104)
WARN  [extractor] Could not publish to NATS server.
```

## Example

For example, connect to a NATS server on `128.0.0.1:1234` using a Bitcoin Core binary in `./build/src/bitcoind` with a bitcoind PID of `45324`:

> [!NOTE]
> Loading the eBPF tracing code into the Linux kernel requires priviledges. Think twice before running code you didn't review on your machine. Ideally, run the ebpf-extractor and Bitcoin Core in a VM.


```
$ cargo run --bin ebpf-extractor -- --nats-address 128.0.0.1:1234 --bitcoind-path ./build/src/bitcoind --bitcoind-pid 45324
```

For automated setups, it's recommended to start `bitcoind` with the `-pid=<file>` argument (defaults to `bitcoind.pid`)
and use `--bitcoind-pid-file <BITCOIND_PID_FILE>` instead of `--bitcoind-pid` when starting the ebpf-extractor.


## Usage

```
$ cargo run --bin ebpf-extractor -- --help
The peer-observer extractor hooks into a Bitcoin Core binary with tracepoints and publishes events into a NATS pub-sub queue

Usage: ebpf-extractor [OPTIONS] --bitcoind-path <BITCOIND_PATH> <--bitcoind-pid <BITCOIND_PID>|--bitcoind-pid-file <BITCOIND_PID_FILE>>

Options:
  -a, --nats-address <ADDRESS>
          The NATS server address the extractor/tool should connect and subscribe to [default: 127.0.0.1:4222]
  -u, --nats-username <USERNAME>
          The NATS username the extractor/tool should try to authentificate to the NATS server with
  -p, --nats-password <PASSWORD>
          The NATS password the extractor/tool should try to authentificate to the NATS server with
  -f, --nats-password-file <PASSWORD_FILE>
          A path to a file containing a password the extractor/tool should try to authentificate to the NATS server with
  -b, --bitcoind-path <BITCOIND_PATH>
          Path to the Bitcoin Core (bitcoind) binary that should be hooked into
      --bitcoind-pid <BITCOIND_PID>
          PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into. Either this or --bitcoind-pid-file must be set
      --bitcoind-pid-file <BITCOIND_PID_FILE>
          File containing the PID (Process ID) of the Bitcoin Core (bitcoind) binary that should be hooked into. Either this or --bitcoind-pid must be set
      --no-p2pmsg-tracepoints
          Controls if the p2p message tracepoints should be hooked into
      --no-connection-tracepoints
          Controls if the connection tracepoints should be hooked into
      --no-mempool-tracepoints
          Controls if the mempool tracepoints should be hooked into
      --no-validation-tracepoints
          Controls if the validation tracepoints should be hooked into
  -l, --log-level <LOG_LEVEL>
          The log level the extractor should run with. Valid log levels are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html [default: DEBUG]
      --libbpf-debug
          If used, libbpf will print debug information about the BPF maps, programs, and tracepoints during extractor startup. This can be useful during debugging
  -i, --no-idle-exit
          The ebpf-extractor will exit if it doesn't detect activity in the ebpf buffers for 180 seconds. This flag disables this and only emits warnings about inactivity. This can be useful during debugging
  -h, --help
          Print help
  -V, --version
          Print version
```
