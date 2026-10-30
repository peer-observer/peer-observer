# alerts

A peer-observer tool that subscribes to NATS events and emits alerts when anomalous
peer behavior is detected.

## Heuristics

### PingSpammer

Detects peers that send more than `--ping-threshold` inbound `ping` messages within a
`--ping-window-secs` second sliding window.

Alert format (as rendered by `LoggingAlerter`):
```
PingSpammer | peer_id=<id> addr=<addr> | <count> pings in last <secs>s (threshold: <threshold>)
```

### AddrSpammer

Detects peers that send more than `--addr-threshold` inbound `addr` or `addrv2` messages
within an `--addr-window-secs` second sliding window. Both message types are counted in
the same window.

Alert format (as rendered by `LoggingAlerter`):
```
AddrSpammer | peer_id=<id> addr=<addr> | <count> addr/addrv2 messages in last <secs>s (threshold: <threshold>)
```

Each peer/kind combination fires at most one alert per session (one-shot).

### MisbehavingPeer

Reports a peer whenever Bitcoin Core flags it as misbehaving, for example for
sending too many headers or an invalid block. Core logs a reason and usually
disconnects the peer right away. The reason is passed on in the alert. The
address is `unknown` if the tool never saw a connection event or message from
the peer, for example because the peer connected before the tool started.

Alert format (as rendered by `LoggingAlerter`):
```
MisbehavingPeer | peer_id=<id> addr=<addr> | <reason>
```

There are no settings for this heuristic. Every report fires an alert.

## Peer lifecycle

When a peer that one of the per-peer heuristics flagged disconnects (either via a
`ConnectionEvent::Close` or by being evicted after `--peer-stale-secs` of
inactivity), the same `Alerter` emits a `PeerDisconnected` alert with how long
the peer stayed around after it was first flagged:

```
PeerDisconnected | peer_id=<id> addr=<addr> | active=<duration>s
```

Non-flagged peers disconnect silently (no alert is emitted).

## Usage

```
cargo run -p alerts -- [OPTIONS]
```

## Options

```
Arguments for the connection the the NATS server that each extractor and tool needs

Usage: alerts [OPTIONS]

Options:
  -a, --nats-address <ADDRESS>
          The NATS server address the extractor/tool should connect and subscribe to [default: 127.0.0.1:4222]
  -u, --nats-username <USERNAME>
          The NATS username the extractor/tool should try to authentificate to the NATS server with
  -p, --nats-password <PASSWORD>
          The NATS password the extractor/tool should try to authentificate to the NATS server with
  -f, --nats-password-file <PASSWORD_FILE>
          A path to a file containing a password the extractor/tool should try to authentificate to the NATS server with
      --ping-threshold <PING_THRESHOLD>
          Number of pings in the window before alerting [default: 3]
      --ping-window-secs <PING_WINDOW_SECS>
          Sliding window size for ping detection (seconds) [default: 120]
      --addr-threshold <ADDR_THRESHOLD>
          Number of addr/addrv2 messages in the window before alerting [default: 6]
      --addr-window-secs <ADDR_WINDOW_SECS>
          Sliding window size for addr detection (seconds) [default: 60]
  -l, --log-level <LOG_LEVEL>
          [default: DEBUG]
      --peer-stale-secs <PEER_STALE_SECS>
          Remove peers not seen for this many seconds (prevents OOM on missed Close events) [default: 300]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Example

```bash
# Use low thresholds for testing
cargo run -p alerts -- \
  --nats-address nats://localhost:4222 \
  --ping-threshold 3 \
  --ping-window-secs 30 \
  --addr-threshold 2 \
  --addr-window-secs 60
```

Example output:
```
INFO  [alerts::alerter] PingSpammer | peer_id=42 addr=1.2.3.4:8333 | 4 pings in last 30s (threshold: 3)
INFO  [alerts::alerter] AddrSpammer | peer_id=7 addr=5.6.7.8:8333 | 3 addr/addrv2 messages in last 60s (threshold: 2)
INFO  [alerts::alerter] PeerDisconnected | peer_id=42 addr=1.2.3.4:8333 | active=47s
```
