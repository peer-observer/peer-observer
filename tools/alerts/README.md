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

### AddrEntriesSpammer

Counts the address *entries* inside `addr`/`addrv2` messages, catching peers that stay under `AddrSpammer`
by sending a few oversized messages.
Uses a per-peer token bucket modeled on Bitcoin Core's addr rate limiting: the bucket starts at
`--addr-entries-initial-tokens` (default `1`) and refills at `--addr-entries-rate-per-sec` entries/s up to
`--addr-entries-bucket-capacity` (default `1000`, Core's `MAX_ADDR_PROCESSING_TOKEN_BUCKET`).
Each entry spends a token and entries hitting an empty bucket count as *rate-limited*.
Both message types share one bucket, and the alert fires once the cumulative rate-limited count exceeds `--addr-entries-threshold`.
Each outbound `GETADDR` adds one capacity-sized allowance to cover the expected response, matching Core's bypass for requested address bursts.

The metric is the count of entries that *exceed Core's rate limit*.

Alert format (as rendered by `LoggingAlerter`):
```
AddrEntriesSpammer | peer_id=<id> addr=<addr> | <count> addr/addrv2 entries rate-limited (threshold: <threshold>, bucket: <capacity>, rate: <rate>/s, getaddr_sent: <count>)
```

Each peer/kind combination fires at most one alert per session (one-shot).

## Peer lifecycle

When a previously flagged peer disconnects (either via a `ConnectionEvent::Close`
or by being evicted after `--peer-stale-secs` of inactivity), the same `Alerter`
emits a `PeerDisconnected` alert with the duration of the spamming episode:

```
PeerDisconnected | peer_id=<id> addr=<addr> | active=<duration>s | flags=[<reason>, ...]
```

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
      --addr-entries-initial-tokens <ADDR_ENTRIES_INITIAL_TOKENS>
          Initial token seed for a peer's addr/addrv2 entry bucket. Mirrors Core's per-peer starting bucket (1.0, "permit self-announcement") [default: 1]
      --addr-entries-bucket-capacity <ADDR_ENTRIES_BUCKET_CAPACITY>
          Token bucket capacity: the refill ceiling for addr/addrv2 entries. Mirrors Core's MAX_ADDR_PROCESSING_TOKEN_BUCKET (1000); the bucket refills up to this [default: 1000]
      --addr-entries-rate-per-sec <ADDR_ENTRIES_RATE_PER_SEC>
          Token refill rate for addr/addrv2 entries (entries per second). Mirrors Core's MAX_ADDR_RATE_PER_SECOND (0.1, i.e. one entry every 10 seconds) [default: 0.1]
      --addr-entries-threshold <ADDR_ENTRIES_THRESHOLD>
          Number of rate-limited addr/addrv2 entries before alerting [default: 20]
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
  --addr-window-secs 60 \
  --addr-entries-initial-tokens 5 \
  --addr-entries-bucket-capacity 5 \
  --addr-entries-threshold 5
```

Example output:
```
INFO  [alerts::alerter] PingSpammer | peer_id=42 addr=1.2.3.4:8333 | 4 pings in last 30s (threshold: 3)
INFO  [alerts::alerter] AddrSpammer | peer_id=7 addr=5.6.7.8:8333 | 3 addr/addrv2 messages in last 60s (threshold: 2)
INFO  [alerts::alerter] AddrEntriesSpammer | peer_id=9 addr=8.8.8.8:8333 | 15 addr/addrv2 entries rate-limited (threshold: 5, bucket: 5, rate: 0.1/s, getaddr_sent: 0)
INFO  [alerts::alerter] PeerDisconnected | peer_id=42 addr=1.2.3.4:8333 | active=47s | flags=[PingSpammer]
```
