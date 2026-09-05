use shared::log;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpammerKind {
    Ping,
    Addr,
}

/// Reason a peer was flagged and kept in state until it disconnected
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeerFlag {
    PingSpammer,
    AddrSpammer,
    AddrEntriesSpammer,
}

impl std::fmt::Display for PeerFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerFlag::PingSpammer => f.write_str("PingSpammer"),
            PeerFlag::AddrSpammer => f.write_str("AddrSpammer"),
            PeerFlag::AddrEntriesSpammer => f.write_str("AddrEntriesSpammer"),
        }
    }
}

/// Every observation the alerts tool publishes flows through this enum
/// `Spammer` is emitted when a peer crosses a configured threshold once
/// `AddrEntriesSpammer` is emitted when a peer's addr/addrv2 entries exhaust a
/// token bucket modeled on Bitcoin Core's addr rate limiting
/// `PeerDisconnected` is emitted when a previously-flagged peer disconnects
#[derive(Clone, Debug, PartialEq)]
pub enum Alert {
    Spammer {
        kind: SpammerKind,
        peer_id: u64,
        addr: String,
        count: usize,
        window_secs: u64,
        threshold: usize,
    },
    AddrEntriesSpammer {
        peer_id: u64,
        addr: String,
        /// Cumulative number of addr/addrv2 entries dropped by the token bucket
        rate_limited: u64,
        /// `rate_limited` value that triggered the alert
        threshold: u64,
        /// Token bucket capacity / refill ceiling (entries)
        bucket_capacity: u64,
        /// Token refill rate (entries per second)
        rate_per_sec: f64,
        /// Number of outbound GETADDR requests observed for this peer
        getaddr_requests_sent: u64,
    },
    PeerDisconnected {
        peer_id: u64,
        addr: String,
        active_secs: u64,
        /// Heuristics that caused this peer to be tracked until disconnect
        flags: Vec<PeerFlag>,
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
            Alert::AddrEntriesSpammer {
                peer_id,
                addr,
                rate_limited,
                threshold,
                bucket_capacity,
                rate_per_sec,
                getaddr_requests_sent,
            } => write!(
                f,
                "AddrEntriesSpammer | peer_id={} addr={} | {} addr/addrv2 entries rate-limited (threshold: {}, bucket: {}, rate: {}/s, getaddr_sent: {})",
                peer_id, addr, rate_limited, threshold, bucket_capacity, rate_per_sec, getaddr_requests_sent
            ),
            Alert::PeerDisconnected {
                peer_id,
                addr,
                active_secs,
                flags,
            } => {
                write!(
                    f,
                    "PeerDisconnected | peer_id={} addr={} | active={}s | flags=[",
                    peer_id, addr, active_secs
                )?;
                for (index, flag) in flags.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{flag}")?;
                }
                f.write_str("]")
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_entries_spammer_display_includes_bucket_rate_and_getaddr_count() {
        let alert = Alert::AddrEntriesSpammer {
            peer_id: 42,
            addr: "203.0.113.5:8333".to_string(),
            rate_limited: 1234,
            threshold: 77,
            bucket_capacity: 1000,
            rate_per_sec: 0.25,
            getaddr_requests_sent: 3,
        };

        assert_eq!(
            alert.to_string(),
            "AddrEntriesSpammer | peer_id=42 addr=203.0.113.5:8333 | 1234 addr/addrv2 entries rate-limited (threshold: 77, bucket: 1000, rate: 0.25/s, getaddr_sent: 3)"
        );
    }

    #[test]
    fn peer_disconnected_display_includes_all_flags() {
        let alert = Alert::PeerDisconnected {
            peer_id: 42,
            addr: "203.0.113.5:8333".to_string(),
            active_secs: 105,
            flags: vec![
                PeerFlag::PingSpammer,
                PeerFlag::AddrSpammer,
                PeerFlag::AddrEntriesSpammer,
            ],
        };

        assert_eq!(
            alert.to_string(),
            "PeerDisconnected | peer_id=42 addr=203.0.113.5:8333 | active=105s | flags=[PingSpammer, AddrSpammer, AddrEntriesSpammer]"
        );
    }

    #[test]
    fn peer_disconnected_display_includes_single_flag() {
        let alert = Alert::PeerDisconnected {
            peer_id: 7,
            addr: "198.51.100.9:8333".to_string(),
            active_secs: 12,
            flags: vec![PeerFlag::AddrEntriesSpammer],
        };

        assert_eq!(
            alert.to_string(),
            "PeerDisconnected | peer_id=7 addr=198.51.100.9:8333 | active=12s | flags=[AddrEntriesSpammer]"
        );
    }
}
