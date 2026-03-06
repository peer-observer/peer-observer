# peer-observer

Tool to monitor for P2P anomalies and attacks using well-behaving, passive
Bitcoin Core honeynodes (honeypot nodes).

## Components and their interaction

The peer-observer consists of multiple components. One or more `extractors` that
extract events from a Bitcoin Core node and multiple `tools` that process the
extracted data. The `extractors` and `tools` are connected with a [nats.io]-based
PUB-SUB connection via a NATS server. The exchanged messages are serialized
protobuf structures.

The `ebpf-extractor` uses the Bitcoin Core tracepoints to extract
events like received and send P2P messages, open and closed P2P connections, mempool
changes, and more. This is implemented using the USDT capabilites of [libbpf-rs].
The Bitcoin P2P protocol messages are deserialized using [rust-bitcoin].

The `rpc-extractor` periodically queries the Bitcoin Core RPC interface using
[corepc]. Results are published to NATS as RPC events.

The `p2p-extractor` receives an inbound connection from a Bitcoin node and publishes
selected P2P measurements as events into a NATS pub-sub queue.

The `log-extractor` publishes them parsed `debug.log` log messages as events to NATS.

And finally an experimental `ipc-extractor` which periodically fetch data from a `bitcoin-node` binary through a UNIX socket created with the `-ipcbind` option. Publishes to NATS as IPC events.

The tools are written in Rust (or any other language that supports NATS 
and protobuf). They subscribe to the NATS server. For example, the `logger` tool 
simply prints out all messages that it receives, the `metrics` tool produces prometheus 
metrics, and the `connectivity-check` tool tests received addresses if they are reachable. 
Rust tools can use the types from the `shared` Rust module to deserialize the Protobuf 
messages. For other languages, types can be generated directly from the Protobuf definitions.

```
                                           protobuf
                                           messages
┌─────────────┐    ┌───────────────┐     ┌─────────┐      ┌──────────────────────┐
│             ├────► ebpf-extractor├─────┤         │      │                      │
│             │    └───────────────┘     │         │      │                      │
│             │                          │         │      │ Tools                │
│             │    ┌───────────────┐     │         │      │                      │
│             ├────► rpc-extractor │─────┤         │      │                      │
│             │    └───────────────┘     │         ├──────┼──►logger             │
│             │                          │         │      │                      │
│   Bitcoin   │    ┌───────────────┐     │ NATS.io ├──────┼──►metrics            │
│             ├────► p2p-extractor │─────┤         │      │                      │
│     Node    │    └───────────────┘     │ PUB-SUB ├──────┼──►websocket          │
│             │                          │         │      │                      │
│             │    ┌───────────────┐     │         ├──────┼──►connectivity-check │
│             ├────► log-extractor │─────┤         │      │                      │
│             │    └───────────────┘     │         │      │   ...                │
│             │                          │         │      │                      │
│             │    ┌───────────────┐     │         │      │                      │
│             ├────► ipc-extractor ├─────┤         │      │                      │
└─────────────┘    └───────────────┘     └─────────┘      └──────────────────────┘

 (edit on asciiflow.com)


```

[nats.io]: https://nats.io
[libbpf-rs]: https://github.com/libbpf/libbpf-rs
[rust-bitcoin]: https://github.com/rust-bitcoin/rust-bitcoin
[corepc]: https://github.com/rust-bitcoin/corepc

## Extractors

Extractors extract events from a Bitcoin Core node and publish them to the connected
NATS server. Each extractor connects to a different interface:

| **extractor** | **description**                       |             **details**             |
|---------------|---------------------------------------|:-----------------------------------:|
| ebpf          | uses tracepoints for real-time events | [extractors/ebpf/](extractors/ebpf) |
| rpc           | periodically fetches RPC for events   | [extractors/rpc/](extractors/rpc)   |
| p2p           |Bitcoin P2P events from an inbound node| [extractors/p2p/](extractors/p2p)   |
| log           | parses the debug.log of a node        | [extractors/log/](extractors/log)   |
| ipc           | Fetch data over via IPC socket (experimental) | [extractors/ipc/](extractors/ipc)    |

## Tools

Tools connect and subscribe to the NATS server to learn about new events. Each
tool uses the events differently:

| **tool**              | **description**                                                                  | **language** | **details**                             |
|-----------------------|----------------------------------------------------------------------------------|--------------|-----------------------------------------|
| logger                | logs events to stdout. Event type can be filtered.                               | `rust`       | [tools/logger/](tools/logger)           |
| metrics               | produces prometheus metrics from events.                                         | `rust`       | [tools/metrics/](tools/metrics)         |
| websocket             | publishes events into a websocket as JSON                                        | `rust`       | [tools/websocket/](tools/websocket)     |
| connectivity-check    | connects to IP addresses received via `addr(v2)` messages and records the result | `rust`       | [tools/connectivity-check/](tools/connectivity-check)    |

## Real-world usage

On public.peer.observer, I run a peer-observer instance with multiple
Bitcoin Core honeynodes. To avoid leaking the IP addresses of these honeynodes
(an P2P attacker would just not attack these), public access is limited.

Setting up a peer-observer instance is non-trivial as hooking into the Bitcoin
Core tracepoints requires elevated system privileges. Additionally, a few not-yet-merged
patches to Bitcoin Core are required at the moment. Documentation is sparse
or non-existent. Feel free to open an issue if you still want to set up an instance and
I'll do my best to add more documentation.


## Development

### Integration tests

To run the integration tests, run with the feature `nats_integration_tests` and
`node_integration_tests`. If you are not using the nix-shell, you need to set the
`NATS_SERVER_BINARY` to the path to your `nats-server` binary. Addtionally,
`BITCOIND_EXE` can be set to a custom `bitcoind` binary. By default, a recent
release will be downloaded and used if `BITCOIND_SKIP_DOWNLOAD` is unset.

```bash
$ cargo test --features nats_integration_tests --features node_integration_tests
```

Test coverage can be generated with:

```bash
$ cargo tarpaulin --out Html --features nats_integration_tests --features node_integration_tests
```

This generates a `tarpaulin-report.html` file which can be viewed in the browser.
