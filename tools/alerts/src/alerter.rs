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
