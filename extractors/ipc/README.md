# `ipc` extractor

> publishes data fetched from IPC

A peer-observer extractor that periodically queries the Bitcoin Core IPC interfaces and publishes the results as events into a NATS pub-sub queue.

## Example

Start `bitcoin-node` with `-ipcbind=unix` to expose the IPC interface over a UNIX socket. With the bare `unix` value the socket is created at `<datadir>/node.sock` relative to the *network* data directory, for instance regtest with a default datadir results in the socket located at `~/.bitcoin/regtest/node.sock`. `~/.bitcoin/node.sock` for mainnet.

For example, run a regtest node and point the ipc-extractor at the generated socket:

```bash
$ bitcoin-node -regtest -ipcbind=unix &
$ cargo run --bin ipc-extractor -- --ipc-socket-path ~/.bitcoin/regtest/node.sock
```

Note that `bitcoin-node` is compiled by setting `-DENABLE_IPC=ON` when building from source. Alternatively, there is also a proxy binary named `bitcoin` that lets you spawn a specific process with the `-m` option. That's it, running `bitcoin -m node -regtest -ipcbind=unix` is equivalent to the start command above.

## Usage

```
$ cargo run --bin ipc-extractor -- --help
The peer-observer ipc-extractor periodically queries data from the Bitcoin Core IPC endpoint and publishes the results as events into a NATS pub-sub queue

Usage: ipc-extractor [OPTIONS] --ipc-socket-path <IPC_SOCKET_PATH>

Options:
  -a, --nats-address <ADDRESS>
          The NATS server address the extractor/tool should connect and subscribe to [default: 127.0.0.1:4222]
  -u, --nats-username <USERNAME>
          The NATS username the extractor/tool should try to authentificate to the NATS server with
  -p, --nats-password <PASSWORD>
          The NATS password the extractor/tool should try to authentificate to the NATS server with
  -f, --nats-password-file <PASSWORD_FILE>
          A path to a file containing a password the extractor/tool should try to authentificate to the NATS server with
  -l, --log-level <LOG_LEVEL>
          The log level the extractor should run with. Valid log levels are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html [default: DEBUG]
      --ipc-socket-path <IPC_SOCKET_PATH>
          A UNIX socket path to read IPC data from
      --query-interval <QUERY_INTERVAL>
          Interval (in seconds) in which to query from the Bitcoin Core IPC interface [default: 10]
  -h, --help
          Print help
  -V, --version
          Print version
```
