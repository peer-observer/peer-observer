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

### VersionTimeOffset

Flags a peer whose `version` message carries a time more than
`--version-time-offset-secs` off the time we received it. Bitcoin Core compares
these times with its own clock and warns the operator when many peers are more
than ten minutes off, since a wrong clock breaks block validation. Seen from the
other side, a peer that far off either runs a broken setup or sends made-up
version messages. The alert carries the signed offset, and the log line the
user agent.

Alert format (as rendered by `LoggingAlerter`):
```
VersionTimeOffset | peer_id=<id> addr=<addr> | version time off by <seconds>s (threshold: <threshold>s)
```

### TxSpy

Flags a peer that asked for transaction relay, has been connected for
`--tx-spy-secs`, and has not sent a single `inv` or `tx` message. Such a peer takes
our transaction announcements and gives nothing back. Normal nodes announce what
they hear elsewhere and send the transactions we request. Monitoring nodes and spy
peers only listen. The check uses `getpeerinfo`, which says per peer whether we
relay transactions to it, when it connected, and how many bytes of each message
type it sent, so it covers peers that connected before the tool started. Each peer
is reported once per connection.

This heuristic needs the rpc-extractor with `getpeerinfo` enabled.

Alert format (as rendered by `LoggingAlerter`):
```
TxSpy | peer_id=<id> addr=<addr> | connected for <seconds>s with transaction relay on, never sent an inv or tx
```

### RepeatedGetaddr

Flags a peer that sends more than `--getaddr-threshold` `getaddr` messages. A
node sends one `getaddr` after the handshake to learn about other nodes. Bitcoin
Core answers only the first one per connection and ignores the rest, so a second
one gains an honest node nothing. Peers that keep asking are address crawlers.
Each peer is reported once.

Alert format (as rendered by `LoggingAlerter`):
```
RepeatedGetaddr | peer_id=<id> addr=<addr> | <count> getaddr messages (threshold: <threshold>)
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

### HighPingWait

Reports when more than `--ping-wait-peers` peers have been waiting longer than
`--ping-wait-secs` for a reply to our ping, according to `getpeerinfo`. Bitcoin
Core pings every peer regularly. One slow peer is normal. Many peers waiting at
once means the problem is on our side: the node is overloaded, its network is
stalling, or the message handling thread is stuck. This was the first visible
sign in peer-observer issue 198. The alert fires once per episode and re-arms
once the count is back at or below the threshold.

This heuristic needs the rpc-extractor with `getpeerinfo` enabled.

Alert format (as rendered by `LoggingAlerter`):
```
HighPingWait | <count> of <total> peers waiting more than <secs>s for a pong (threshold: <threshold> peers)
```

### LowOutboundPeers

Reports when `getpeerinfo` has shown fewer than `--min-outbound-peers` full-relay
outbound peers for `--low-outbound-secs`. Bitcoin Core keeps eight of them and
replaces a lost one on its own, but finding a new peer can take a while, so a
dip to seven for half a minute is normal and ignored. Staying below for minutes
means the node cannot find or reach peers: the network is down, the addrman is
poisoned, or something blocks outbound connections. Outbound peers are the ones
we chose ourselves, so losing them also makes the node easier to eclipse. The
alert fires once per episode.

This heuristic needs the rpc-extractor with `getpeerinfo` enabled.

Alert format (as rendered by `LoggingAlerter`):
```
LowOutboundPeers | <count> full-relay outbound peers connected, below <threshold> for <seconds>s| <count> full-relay outbound peers connected (threshold: <threshold>)
```

### NetgroupFleet

Reports a netgroup, a /16 for IPv4 or a /32 for IPv6, that holds more than
`--fleet-threshold` of our inbound connections according to `getpeerinfo`.
Bitcoin Core spreads its outbound peers over netgroups so no single network can
surround it, but anyone can open many inbound connections. A netgroup with an
outsized share of our inbound slots is one operator running many nodes, or one
party trying to occupy our slots. Only IPv4 and IPv6 peers are grouped: onion,
I2P and CJDNS peers have no address to group by, inbound Tor connections all show
up as localhost, and peers on private or loopback addresses are the operator's
own tools. The alert fires once per netgroup until the group shrinks back to the
threshold.

This heuristic needs the rpc-extractor with `getpeerinfo` enabled.

Alert format (as rendered by `LoggingAlerter`):
```
NetgroupFleet | <count> of <total> inbound peers are from <netgroup> (threshold: <threshold>)
```

### MisbehavingBurst

Reports when Bitcoin Core flags more than `--misbehaving-burst-threshold` peers
as misbehaving within `--misbehaving-burst-window-secs`. A single misbehaving
peer is one bad actor or a bug, and `MisbehavingPeer` reports each one. Many
reports within minutes point at something bigger: a coordinated set of peers, a
client release with a bug, or a change on our side that makes us reject peers.
The alert fires once per episode.

Alert format (as rendered by `LoggingAlerter`):
```
MisbehavingBurst | <count> peers reported as misbehaving in last <secs>s (threshold: <threshold>)
```

### ConnectionCycling

Reports an address that opened more than `--cycling-threshold` inbound
connections within `--cycling-window-secs`. A node connects once and stays. An
address that comes back every few minutes is cycling connections: a crawler
returning for more addresses, a monitor trying to be the first to hear our
transactions, or software stuck in a reconnect loop. Each connection gets a fresh
peer id, so the per-peer alerts repeat for it, while this one fires once per
episode per address and, for an address that keeps cycling, at most once per
`--cycling-repeat-secs`, a day by default. Connections from localhost are not counted: inbound Tor
connections all arrive there and cannot be told apart by address.

Alert format (as rendered by `LoggingAlerter`):
```
ConnectionCycling | <host> opened <count> connections in last <secs>s (threshold: <threshold>)
```

### AddressHarvester

Reports a netgroup, a /16 for IPv4 or a /32 for IPv6, from which more than
`--harvester-threshold` connections within `--harvester-window-secs` sent a
`getaddr` and closed within `--harvester-max-age-secs`. That is what an address
crawler looks like: connect, finish the handshake, collect addresses, leave. One
such connection is nothing to report, and the demo node sees several per minute,
so they are counted per netgroup. Inbound Tor connections all arrive from
localhost and cannot be told apart, so they count as one group named
`onion inbound`. The operator's own local tools are left out. A group that keeps
harvesting is reported at most once per `--harvester-repeat-secs`, an hour by
default; in a live run one Tor exit range would otherwise have been reported every
ten minutes for seven hours.

Alert format (as rendered by `LoggingAlerter`):
```
AddressHarvester | <count> connections from <netgroup> asked for addresses and left within <secs>s in last <window>s (threshold: <threshold>)
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

## Combined verdict

### SuspiciousPeer

Reports an address once `--suspicious-flags` different per-peer alert kinds have
fired against it within `--suspicious-window-secs`. A single alert about a peer
says that it is odd, and any one of them has an innocent explanation. Two or more
independent ones on the same address within an hour rarely do. The verdict works
per address rather than per connection, so a peer that reconnects with a fresh
peer id keeps its flags, and `ConnectionCycling` counts as a flag for its
address. `PeerDisconnected` does not count. Inbound Tor
connections all arrive from localhost, so they are judged per connection instead
of per address, and the operator's own local tools are left out. An address is
reported once per window.

Alert format (as rendered by `LoggingAlerter`):
```
SuspiciousPeer | host=<host> | <count> alert kinds in last <secs>s: <kind>, <kind>
```

## Peer lifecycle

When a peer that one of the per-peer heuristics flagged disconnects (either via a
`ConnectionEvent::Close` or by being evicted after `--peer-stale-secs` of
inactivity), the same `Alerter` emits a `PeerDisconnected` alert with how long
the peer stayed around after it was first flagged:

```
PeerDisconnected | peer_id=<id> addr=<addr> | active=<duration>s
```

Non-flagged peers disconnect silently (no alert is emitted). Peers that leave
within `--disconnect-min-active-secs` of being flagged are not reported either:
crawlers that trip a handshake or `getaddr` check typically close the connection in
the same second, and the alert that flagged them already says everything.

Alerts about a single peer are logged with the user agent from the peer's
`version` message when the tool saw it, for example
`PingSpammer | peer_id=63 addr=1.2.3.4:8333 | 4 pings in last 120s (threshold: 3) | user agent: /Satoshi:28.0.0/`.
This is where crawlers and monitoring nodes usually give themselves away.

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
      --version-time-offset-secs <VERSION_TIME_OFFSET_SECS>
          Alert when a peer's version message time is off by more than this many seconds [default: 600]
      --tx-spy-secs <TX_SPY_SECS>
          Alert when a peer with transaction relay on has sent no inv or tx after this many seconds [default: 600]
      --getaddr-threshold <GETADDR_THRESHOLD>
          Number of getaddr messages from one peer before alerting [default: 1]
      --slow-block-secs <SLOW_BLOCK_SECS>
          Alert when connecting a block takes longer than this many seconds [default: 60]
      --stale-tip-secs <STALE_TIP_SECS>
          Alert when no block has been connected for this many seconds [default: 7200]
      --cycling-threshold <CYCLING_THRESHOLD>
          Number of inbound connections from one address in the window before alerting [default: 10]
      --cycling-window-secs <CYCLING_WINDOW_SECS>
          Sliding window size for connection cycling detection (seconds) [default: 3600]
      --cycling-repeat-secs <CYCLING_REPEAT_SECS>
          Report an address that keeps cycling at most once per this many seconds [default: 86400]
      --harvester-threshold <HARVESTER_THRESHOLD>
          Number of short connections asking for addresses from one netgroup before alerting [default: 3]
      --harvester-window-secs <HARVESTER_WINDOW_SECS>
          Sliding window size for address harvester detection (seconds) [default: 600]
      --harvester-max-age-secs <HARVESTER_MAX_AGE_SECS>
          A connection that asked for addresses counts as harvesting if it closed within this many seconds [default: 30]
      --harvester-repeat-secs <HARVESTER_REPEAT_SECS>
          Report a netgroup that keeps harvesting at most once per this many seconds [default: 3600]
      --misbehaving-burst-threshold <MISBEHAVING_BURST_THRESHOLD>
          Number of misbehaving reports in the window before alerting [default: 5]
      --misbehaving-burst-window-secs <MISBEHAVING_BURST_WINDOW_SECS>
          Sliding window size for misbehaving reports (seconds) [default: 600]
      --ping-wait-secs <PING_WAIT_SECS>
          A ping counts as waiting too long after this many seconds without a pong [default: 5]
      --ping-wait-peers <PING_WAIT_PEERS>
          Number of peers waiting too long for a pong before alerting [default: 10]
      --min-outbound-peers <MIN_OUTBOUND_PEERS>
          Alert when fewer than this many full-relay outbound peers are connected [default: 8]
      --low-outbound-secs <LOW_OUTBOUND_SECS>
          Only alert once the outbound peer count has been low for this many seconds [default: 120]
      --fleet-threshold <FLEET_THRESHOLD>
          Number of inbound peers from one netgroup before alerting [default: 8]
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
      --suspicious-flags <SUSPICIOUS_FLAGS>
          Number of different alert kinds on one address before calling it suspicious [default: 2]
      --suspicious-window-secs <SUSPICIOUS_WINDOW_SECS>
          How long an alert counts towards an address being suspicious (seconds) [default: 3600]
  -m, --metrics-address <METRICS_ADDRESS>
          The metrics server address the tool should listen on [default: 127.0.0.1:8283]
  -l, --log-level <LOG_LEVEL>
          [default: DEBUG]
      --peer-stale-secs <PEER_STALE_SECS>
          Remove peers not seen for this many seconds (prevents OOM on missed Close events) [default: 300]
      --disconnect-min-active-secs <DISCONNECT_MIN_ACTIVE_SECS>
          Only report the disconnect of a flagged peer if it stayed at least this many seconds after being flagged [default: 1]
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
