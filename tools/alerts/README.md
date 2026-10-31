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

### HandshakeAfterVerack

Flags a peer that sends a handshake message after its own `verack`. The P2P
handshake is `version`, optional feature messages like `wtxidrelay` and
`sendaddrv2`, and then `verack`. Bitcoin Core ignores `version`, `verack`,
`wtxidrelay`, and `sendaddrv2` messages after the handshake and disconnects
peers sending `sendtxrcncl` after it. Peers doing this are buggy or probing.

The check only starts once the tool has seen the peer's `verack`, so peers that
connected before the tool started are not checked. Each peer is reported once.

Alert format (as rendered by `LoggingAlerter`):
```
HandshakeAfterVerack | peer_id=<id> addr=<addr> | received <command> after verack
```

There are no settings for this heuristic.

### SmallPingNonce

Flags a peer that sends more than `--small-ping-nonce-threshold` `ping` messages
with a nonce below 2^32. Bitcoin Core draws eight random bytes for every ping
nonce, so a nonce that small happens about once in four billion pings. A peer
sending several of them uses a counter or a 32-bit random number and is not a
Bitcoin Core node, whatever its user agent says. Each peer is reported once.

Alert format (as rendered by `LoggingAlerter`):
```
SmallPingNonce | peer_id=<id> addr=<addr> | <count> pings with a nonce below 2^32 (threshold: <threshold>)
```

### TxRelayMismatch

Flags a peer that announces or sends transactions after asking us not to relay
transactions to it. A peer sets `relay=false` in its `version` message when it
is not interested in unconfirmed transactions, as block-relay-only connections
and nodes running with `-blocksonly` do. Such a node has no transactions to
share either. One that still sends `inv` messages with transactions or `tx`
messages is behaving inconsistently. A peer that loads a bloom filter
(`filterload` or `filterclear`, BIP 37) has turned relay back on and is no longer
checked.

Only peers whose `version` message the tool saw are checked. Each peer is
reported once.

Alert format (as rendered by `LoggingAlerter`):
```
TxRelayMismatch | peer_id=<id> addr=<addr> | received <command> with transactions after relay=false in its version message
```

There are no settings for this heuristic.

### UnknownMessages

Flags a peer that sends more than `--unknown-message-threshold` messages whose
command the extractor does not know. Bitcoin Core ignores such messages. One or
two can be a newer client with a feature we do not parse yet. A peer sending many
of them is fuzzing, probing how we react, or badly broken. The alert names the
last unknown command. Each peer is reported once.

Alert format (as rendered by `LoggingAlerter`):
```
UnknownMessages | peer_id=<id> addr=<addr> | <count> unknown messages (threshold: <threshold>), last: <command>
```

## Node heuristics

These look at the node itself rather than at a single peer.

### SlowBlock

Reports a block that took Bitcoin Core longer than `--slow-block-secs` to
connect. Connecting a block means checking all its transactions and updating
the UTXO set, which takes well under a second for most blocks on a healthy
node. A block that takes much longer points at an unusual block, a slow disk,
or a node under load. Every slow block is reported.

Alert format (as rendered by `LoggingAlerter`):
```
SlowBlock | height=<height> hash=<hash> | connected in <seconds>s (threshold: <threshold>s), <n> transactions, <n> inputs, <n> sigops
```

### StaleTip

Reports when the node has not connected a block for `--stale-tip-secs`. Blocks
arrive about every ten minutes on average, and two hours without one happen
only a handful of times per year on mainnet. Going longer means the node lost
its peers, the network split, or the data pipeline feeding this tool broke. The
clock starts when the tool starts, so a node that never delivers a block is
reported too.

The alert fires once per stale period. When the next block connects, a
`TipRecovered` alert reports how long the tip was stale.

Alert formats (as rendered by `LoggingAlerter`):
```
StaleTip | no block connected for <seconds>s (threshold: <threshold>s), last height: <height or unknown>
TipRecovered | height=<height> | block connected after <seconds>s without a block
```

### InboundConnectionDrops

Reports when more than `--inbound-drop-threshold` inbound connections that had
been up for at least `--inbound-drop-min-age-secs` close within
`--inbound-drop-window-secs`. Inbound peers come and go. On a reachable node most
inbound connections are crawlers that leave within seconds, so those are ignored.
Many established inbound peers leaving at once points at a problem: the node
became unreachable, a provider has network trouble, or a group of peers
controlled by one party left together.

Connections that Bitcoin Core evicted itself are not counted either. Core only
evicts when its inbound slots are full, and those drops are routine. The alert
fires once per episode: after an alert it stays quiet until the count in the
window has fallen back to the threshold and a full window has passed, so a
steady rate right around the threshold is reported once per window.

Alert format (as rendered by `LoggingAlerter`):
```
InboundConnectionDrops | <count> inbound connections older than <age>s closed in last <secs>s (threshold: <threshold>), evictions not counted
| <count> inbound connections closed in last <secs>s (threshold: <threshold>), evictions not counted
```

### OldConnectionDrops

Reports when more than `--old-connection-drop-threshold` connections that had
been up for at least `--old-connection-age-secs` close within
`--old-connection-drop-window-secs`. Long-lived connections are the stable part
of a node's peer set: well-connected nodes and our own outbound peers. Losing
several of them at once is unusual and points at network trouble, a peer
operator restarting many nodes, or someone cycling connections to us.

The connection age comes from the time Bitcoin Core established the connection,
which it reports when the connection closes. Inbound and outbound connections
count alike, evicted ones included. The alert fires once per episode, like
`InboundConnectionDrops`.

Alert format (as rendered by `LoggingAlerter`):
```
OldConnectionDrops | <count> connections older than <age>s closed in last <secs>s (threshold: <threshold>)
```

## Peer lifecycle

When a peer that one of the per-peer heuristics flagged disconnects (either via a
`ConnectionEvent::Close` or by being evicted after `--peer-stale-secs` of
inactivity), the same `Alerter` emits a `PeerDisconnected` alert with how long
the peer stayed around after it was first flagged:

```
PeerDisconnected | peer_id=<id> addr=<addr> | active=<duration>s
```

Non-flagged peers disconnect silently (no alert is emitted).

## Metrics

The tool serves Prometheus metrics on `--metrics-address`. Besides the start
timestamp, it exports:

```
peerobserver_alerts_total{alert="<kind>"}
peerobserver_alerts_last_fired_timestamp{alert="<kind>"}
peerobserver_alerts_flagged_peers{alert="<kind>"}
peerobserver_alerts_flagged_peer_info{alert="<kind>",peer_id="<id>",addr="<addr>"}
```

`<kind>` is the alert name in snake case, for example `ping_spammer`,
`misbehaving_peer`, or `stale_tip`. The counter and the two per-kind gauges are
present for every kind from the start, with zero, so a dashboard can show which
alerts fired and a Grafana alert can fire on an increase. The timestamp is the
UNIX time the kind last fired, or zero.

`alerts_flagged_peers` counts the connected peers each per-peer alert flagged,
and `alerts_flagged_peer_info` has one series per flagged peer, always 1. Both
drop the peer when it disconnects or goes stale. Kinds that are not about a
single peer stay at zero.

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
      --small-ping-nonce-threshold <SMALL_PING_NONCE_THRESHOLD>
          Number of pings with a nonce below 2^32 from one peer before alerting [default: 3]
      --unknown-message-threshold <UNKNOWN_MESSAGE_THRESHOLD>
          Number of unknown messages from one peer before alerting [default: 3]
      --slow-block-secs <SLOW_BLOCK_SECS>
          Alert when connecting a block takes longer than this many seconds [default: 60]
      --stale-tip-secs <STALE_TIP_SECS>
          Alert when no block has been connected for this many seconds [default: 7200]
      --inbound-drop-threshold <INBOUND_DROP_THRESHOLD>
          Number of inbound connections closed in the window before alerting [default: 20]
      --inbound-drop-window-secs <INBOUND_DROP_WINDOW_SECS>
          Sliding window size for inbound connection drops (seconds) [default: 300]
      --inbound-drop-min-age-secs <INBOUND_DROP_MIN_AGE_SECS>
          Only count closed inbound connections that were up for at least this many seconds [default: 60]
      --old-connection-drop-threshold <OLD_CONNECTION_DROP_THRESHOLD>
          Number of old connections closed in the window before alerting [default: 5]
      --old-connection-drop-window-secs <OLD_CONNECTION_DROP_WINDOW_SECS>
          Sliding window size for old connection drops (seconds) [default: 300]
      --old-connection-age-secs <OLD_CONNECTION_AGE_SECS>
          A connection counts as old once it has been up for this many seconds [default: 86400]
  -m, --metrics-address <METRICS_ADDRESS>
          The metrics server address the tool should listen on [default: 127.0.0.1:8283]
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
