use shared::log;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpammerKind {
    Ping,
    Addr,
}

/// Every observation the alerts tool publishes flows through this enum
/// `Spammer` is emitted when a peer crosses a configured threshold once
/// `PeerDisconnected` is emitted when a previously-flagged peer disconnects
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    Spammer {
        kind: SpammerKind,
        peer_id: u64,
        addr: String,
        count: usize,
        window_secs: u64,
        threshold: usize,
    },
    PeerDisconnected {
        peer_id: u64,
        addr: String,
        active_secs: u64,
    },
    /// Bitcoin Core reported the peer as misbehaving and gave a reason
    MisbehavingPeer {
        peer_id: u64,
        addr: String,
        reason: String,
    },
    /// The peer sent a handshake message after its handshake was complete
    HandshakeAfterVerack {
        peer_id: u64,
        addr: String,
        command: String,
    },
    /// The peer sent too many pings with a nonce that fits into 32 bits
    SmallPingNonce {
        peer_id: u64,
        addr: String,
        count: usize,
        threshold: usize,
    },
    /// The peer asked for no transaction relay but sent us transactions
    TxRelayMismatch {
        peer_id: u64,
        addr: String,
        command: String,
    },
    /// Bitcoin Core took longer than the threshold to connect a block
    SlowBlock {
        height: i32,
        hash: String,
        connection_time_ms: u64,
        threshold_secs: u64,
        transactions: i64,
        inputs: i32,
        sigops: i64,
    },
    /// No block has been connected for longer than the threshold
    StaleTip {
        since_secs: u64,
        threshold_secs: u64,
        last_height: Option<i32>,
    },
    /// A block connected after the tip had been reported as stale
    TipRecovered { height: i32, stale_secs: u64 },
    /// Many established inbound connections closed within the window,
    /// evictions aside
    InboundConnectionDrops {
        count: usize,
        window_secs: u64,
        threshold: usize,
        min_age_secs: u64,
    },
    /// Several long-lived connections closed within the window
    OldConnectionDrops {
        count: usize,
        window_secs: u64,
        threshold: usize,
        min_age_secs: u64,
    },
    /// The peer sent too many messages we do not know
    UnknownMessages {
        peer_id: u64,
        addr: String,
        count: usize,
        threshold: usize,
        last_command: String,
    },
    /// The time in the peer's version message is far off ours
    VersionTimeOffset {
        peer_id: u64,
        addr: String,
        offset_secs: i64,
        threshold_secs: u64,
        user_agent: String,
    },
    /// Bitcoin Core reported many misbehaving peers within the window
    MisbehavingBurst {
        count: usize,
        window_secs: u64,
        threshold: usize,
    },
}

impl Alert {
    /// The names of all alert kinds, as `name()` returns them. Used to create
    /// a metric series for every kind up front.
    pub const NAMES: [&'static str; 15] = [
        "ping_spammer",
        "addr_spammer",
        "peer_disconnected",
        "misbehaving_peer",
        "handshake_after_verack",
        "small_ping_nonce",
        "tx_relay_mismatch",
        "slow_block",
        "stale_tip",
        "tip_recovered",
        "inbound_connection_drops",
        "old_connection_drops",
        "unknown_messages",
        "version_time_offset",
        "misbehaving_burst",
    ];

    /// A short, stable name for the kind of alert, used as metric label.
    pub fn name(&self) -> &'static str {
        match self {
            Alert::Spammer {
                kind: SpammerKind::Ping,
                ..
            } => "ping_spammer",
            Alert::Spammer {
                kind: SpammerKind::Addr,
                ..
            } => "addr_spammer",
            Alert::PeerDisconnected { .. } => "peer_disconnected",
            Alert::MisbehavingPeer { .. } => "misbehaving_peer",
            Alert::HandshakeAfterVerack { .. } => "handshake_after_verack",
            Alert::SmallPingNonce { .. } => "small_ping_nonce",
            Alert::TxRelayMismatch { .. } => "tx_relay_mismatch",
            Alert::SlowBlock { .. } => "slow_block",
            Alert::StaleTip { .. } => "stale_tip",
            Alert::TipRecovered { .. } => "tip_recovered",
            Alert::InboundConnectionDrops { .. } => "inbound_connection_drops",
            Alert::OldConnectionDrops { .. } => "old_connection_drops",
            Alert::UnknownMessages { .. } => "unknown_messages",
            Alert::VersionTimeOffset { .. } => "version_time_offset",
            Alert::MisbehavingBurst { .. } => "misbehaving_burst",
        }
    }

    /// The peer this alert flags, if it is about a single peer. The
    /// `PeerDisconnected` alert reports a flagged peer leaving and flags none.
    pub fn flagged_peer(&self) -> Option<(u64, &str)> {
        match self {
            Alert::Spammer { peer_id, addr, .. }
            | Alert::MisbehavingPeer { peer_id, addr, .. }
            | Alert::HandshakeAfterVerack { peer_id, addr, .. }
            | Alert::SmallPingNonce { peer_id, addr, .. }
            | Alert::TxRelayMismatch { peer_id, addr, .. }
            | Alert::UnknownMessages { peer_id, addr, .. }
            | Alert::VersionTimeOffset { peer_id, addr, .. } => Some((*peer_id, addr)),
            Alert::PeerDisconnected { .. }
            | Alert::SlowBlock { .. }
            | Alert::StaleTip { .. }
            | Alert::TipRecovered { .. }
            | Alert::InboundConnectionDrops { .. }
            | Alert::OldConnectionDrops { .. }
            | Alert::MisbehavingBurst { .. } => None,
        }
    }
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Alert::Spammer {
                kind,
                peer_id,
                addr,
                count,
                window_secs,
                threshold,
            } => {
                let (name, unit) = match kind {
                    SpammerKind::Ping => ("PingSpammer", "pings"),
                    SpammerKind::Addr => ("AddrSpammer", "addr/addrv2 messages"),
                };
                write!(
                    f,
                    "{} | peer_id={} addr={} | {} {} in last {}s (threshold: {})",
                    name, peer_id, addr, count, unit, window_secs, threshold
                )
            }
            Alert::PeerDisconnected {
                peer_id,
                addr,
                active_secs,
            } => write!(
                f,
                "PeerDisconnected | peer_id={} addr={} | active={}s",
                peer_id, addr, active_secs
            ),
            Alert::MisbehavingPeer {
                peer_id,
                addr,
                reason,
            } => write!(
                f,
                "MisbehavingPeer | peer_id={} addr={} | {}",
                peer_id, addr, reason
            ),
            Alert::HandshakeAfterVerack {
                peer_id,
                addr,
                command,
            } => write!(
                f,
                "HandshakeAfterVerack | peer_id={} addr={} | received {} after verack",
                peer_id, addr, command
            ),
            Alert::SmallPingNonce {
                peer_id,
                addr,
                count,
                threshold,
            } => write!(
                f,
                "SmallPingNonce | peer_id={} addr={} | {} pings with a nonce below 2^32 (threshold: {})",
                peer_id, addr, count, threshold
            ),
            Alert::TxRelayMismatch {
                peer_id,
                addr,
                command,
            } => write!(
                f,
                "TxRelayMismatch | peer_id={} addr={} | received {} with transactions after relay=false in its version message",
                peer_id, addr, command
            ),
            Alert::SlowBlock {
                height,
                hash,
                connection_time_ms,
                threshold_secs,
                transactions,
                inputs,
                sigops,
            } => write!(
                f,
                "SlowBlock | height={} hash={} | connected in {:.1}s (threshold: {}s), {} transactions, {} inputs, {} sigops",
                height,
                hash,
                *connection_time_ms as f64 / 1000.0,
                threshold_secs,
                transactions,
                inputs,
                sigops
            ),
            Alert::StaleTip {
                since_secs,
                threshold_secs,
                last_height,
            } => {
                let last_height = match last_height {
                    Some(height) => height.to_string(),
                    None => "unknown".to_string(),
                };
                write!(
                    f,
                    "StaleTip | no block connected for {}s (threshold: {}s), last height: {}",
                    since_secs, threshold_secs, last_height
                )
            }
            Alert::TipRecovered { height, stale_secs } => write!(
                f,
                "TipRecovered | height={} | block connected after {}s without a block",
                height, stale_secs
            ),
            Alert::InboundConnectionDrops {
                count,
                window_secs,
                threshold,
                min_age_secs,
            } => write!(
                f,
                "InboundConnectionDrops | {} inbound connections older than {}s closed in last {}s (threshold: {}), evictions not counted",
                count, min_age_secs, window_secs, threshold
            ),
            Alert::OldConnectionDrops {
                count,
                window_secs,
                threshold,
                min_age_secs,
            } => write!(
                f,
                "OldConnectionDrops | {} connections older than {}s closed in last {}s (threshold: {})",
                count, min_age_secs, window_secs, threshold
            ),
            Alert::UnknownMessages {
                peer_id,
                addr,
                count,
                threshold,
                last_command,
            } => write!(
                f,
                "UnknownMessages | peer_id={} addr={} | {} unknown messages (threshold: {}), last: {}",
                peer_id, addr, count, threshold, last_command
            ),
            Alert::VersionTimeOffset {
                peer_id,
                addr,
                offset_secs,
                threshold_secs,
                user_agent: _,
            } => write!(
                f,
                "VersionTimeOffset | peer_id={} addr={} | version time off by {}s (threshold: {}s)",
                peer_id, addr, offset_secs, threshold_secs
            ),
            Alert::MisbehavingBurst {
                count,
                window_secs,
                threshold,
            } => write!(
                f,
                "MisbehavingBurst | {} peers reported as misbehaving in last {}s (threshold: {})",
                count, window_secs, threshold
            ),
        }
    }
}

/// Output sink for alerts. Implementations decide how alerts are published
///
/// `emit` is called from the event loop and must not block. Sinks that do I/O
/// (HTTP, NATS publish, Prometheus push, etc.) must own a background task and
/// hand off the alert through a channel — do the network work there, not here
pub trait Alerter: Send + Sync {
    fn emit(&self, alert: Alert);
}

/// Default alerter: writes each alert to the logger at `info!` level
pub struct LoggingAlerter;

impl Alerter for LoggingAlerter {
    fn emit(&self, alert: Alert) {
        log::info!("{}", alert);
    }
}

/// Alerter that pushes each emitted alert through an mpsc channel
/// Lets tests assert on structured alerts instead of parsing log output
#[cfg(any(test, feature = "nats_integration_tests"))]
pub struct IntegrationTestAlerter {
    tx: shared::tokio::sync::mpsc::UnboundedSender<Alert>,
}

#[cfg(any(test, feature = "nats_integration_tests"))]
impl IntegrationTestAlerter {
    pub fn new() -> (Self, shared::tokio::sync::mpsc::UnboundedReceiver<Alert>) {
        let (tx, rx) = shared::tokio::sync::mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

#[cfg(any(test, feature = "nats_integration_tests"))]
impl Alerter for IntegrationTestAlerter {
    fn emit(&self, alert: Alert) {
        let _ = self.tx.send(alert);
    }
}
