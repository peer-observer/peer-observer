//! Combines the per-peer alerts into one verdict per address.
//!
//! A single alert about a peer says that it is odd: it uses a counter as ping
//! nonce, or its clock is off, or it reconnects a lot. Any one of these has an
//! innocent explanation. Two or more independent ones on the same address
//! within an hour rarely do. This is not a heuristic over events but over the
//! alerts the other heuristics produce, and it works per address rather than
//! per connection, so a peer that reconnects with a fresh peer id keeps its
//! flags.

use super::{host_of, is_loopback, Peers, NETWORK_UNROUTABLE};
use crate::alerter::Alert;
use shared::clap;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_SUSPICIOUS_FLAGS: usize = 2;
pub const DEFAULT_SUSPICIOUS_WINDOW_SECS: u64 = 3600;

#[derive(clap::Args, Debug, Clone)]
pub struct SuspiciousPeerArgs {
    /// Number of different alert kinds on one address before calling it suspicious
    #[arg(long, default_value_t = DEFAULT_SUSPICIOUS_FLAGS)]
    pub suspicious_flags: usize,

    /// How long an alert counts towards an address being suspicious (seconds)
    #[arg(long, default_value_t = DEFAULT_SUSPICIOUS_WINDOW_SECS)]
    pub suspicious_window_secs: u64,
}

impl Default for SuspiciousPeerArgs {
    fn default() -> Self {
        SuspiciousPeerArgs {
            suspicious_flags: DEFAULT_SUSPICIOUS_FLAGS,
            suspicious_window_secs: DEFAULT_SUSPICIOUS_WINDOW_SECS,
        }
    }
}

#[derive(Default)]
struct HostFlags {
    /// Alert kinds seen for this host and when each was last seen.
    kinds: Vec<(&'static str, Instant)>,
    reported_at: Option<Instant>,
}

pub struct SuspiciousPeer {
    args: SuspiciousPeerArgs,
    hosts: HashMap<String, HostFlags>,
}

impl SuspiciousPeer {
    pub fn new(args: SuspiciousPeerArgs) -> Self {
        SuspiciousPeer {
            args,
            hosts: HashMap::new(),
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.args.suspicious_window_secs)
    }

    /// The host an alert flags, if it flags one.
    fn flagged_host(alert: &Alert, peers: &Peers) -> Option<String> {
        match alert {
            Alert::ConnectionCycling { host, .. } => Some(host.clone()),
            // The disconnect notice and the verdict itself are not flags.
            Alert::SuspiciousPeer { .. } | Alert::PeerDisconnected { .. } => None,
            other => {
                let (peer_id, addr) = other.flagged_peer()?;
                if !is_loopback(addr) {
                    return Some(host_of(addr).to_string());
                }
                // Inbound Tor connections all arrive from localhost, so they
                // are kept apart by connection. A local tool is left out.
                match peers.get(&peer_id).and_then(|peer| peer.network) {
                    Some(NETWORK_UNROUTABLE) => None,
                    _ => Some(format!("onion inbound peer {}", peer_id)),
                }
            }
        }
    }

    /// Takes note of an alert and returns a `SuspiciousPeer` alert if the
    /// address now has enough different alert kinds against it.
    pub fn on_alert(&mut self, alert: &Alert, peers: &Peers, now: Instant) -> Option<Alert> {
        let host = Self::flagged_host(alert, peers)?;
        let window = self.window();
        let flags = self.hosts.entry(host.clone()).or_default();
        flags
            .kinds
            .retain(|(_, seen)| now.duration_since(*seen) <= window);
        match flags
            .kinds
            .iter_mut()
            .find(|(kind, _)| *kind == alert.name())
        {
            Some(entry) => entry.1 = now,
            None => flags.kinds.push((alert.name(), now)),
        }
        if flags.kinds.len() < self.args.suspicious_flags {
            return None;
        }
        if flags
            .reported_at
            .is_some_and(|at| now.duration_since(at) <= window)
        {
            return None;
        }
        flags.reported_at = Some(now);
        let mut kinds: Vec<&'static str> = flags.kinds.iter().map(|(kind, _)| *kind).collect();
        kinds.sort_unstable();
        Some(Alert::SuspiciousPeer {
            host,
            flags: kinds,
            window_secs: self.args.suspicious_window_secs,
        })
    }

    /// Forgets addresses without recent alerts.
    pub fn prune(&mut self, now: Instant) {
        let window = self.window();
        self.hosts.retain(|_, flags| {
            flags
                .kinds
                .retain(|(_, seen)| now.duration_since(*seen) <= window);
            !flags.kinds.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerter::SpammerKind;

    fn spammer(addr: &str) -> Alert {
        Alert::Spammer {
            kind: SpammerKind::Ping,
            peer_id: 1,
            addr: addr.to_string(),
            count: 4,
            window_secs: 120,
            threshold: 3,
        }
    }

    fn nonce(addr: &str) -> Alert {
        Alert::SmallPingNonce {
            peer_id: 1,
            addr: addr.to_string(),
            count: 4,
            threshold: 3,
        }
    }

    #[test]
    fn two_kinds_on_one_address_make_it_suspicious_once_per_window() {
        let mut suspicious = SuspiciousPeer::new(SuspiciousPeerArgs {
            suspicious_flags: 2,
            suspicious_window_secs: 60,
        });
        let peers = Peers::new();
        let t0 = Instant::now();
        // Same kind twice is still one flag, even from a new connection
        assert_eq!(
            suspicious.on_alert(&spammer("1.2.3.4:1000"), &peers, t0),
            None
        );
        assert_eq!(
            suspicious.on_alert(&spammer("1.2.3.4:1001"), &peers, t0),
            None
        );
        // Another address does not add up
        assert_eq!(
            suspicious.on_alert(&nonce("9.9.9.9:1000"), &peers, t0),
            None
        );
        assert_eq!(
            suspicious.on_alert(&nonce("1.2.3.4:1002"), &peers, t0 + Duration::from_secs(10)),
            Some(Alert::SuspiciousPeer {
                host: "1.2.3.4".to_string(),
                flags: vec!["ping_spammer", "small_ping_nonce"],
                window_secs: 60,
            })
        );
        assert_eq!(
            suspicious.on_alert(
                &spammer("1.2.3.4:1003"),
                &peers,
                t0 + Duration::from_secs(20)
            ),
            None,
            "reported once per window"
        );

        // After the window the flags are gone and it starts over
        suspicious.prune(t0 + Duration::from_secs(200));
        assert!(suspicious.hosts.is_empty());
        assert_eq!(
            suspicious.on_alert(
                &spammer("1.2.3.4:1004"),
                &peers,
                t0 + Duration::from_secs(200)
            ),
            None
        );
    }

    #[test]
    fn disconnects_and_verdicts_do_not_count_as_flags() {
        let mut suspicious = SuspiciousPeer::new(SuspiciousPeerArgs {
            suspicious_flags: 1,
            suspicious_window_secs: 60,
        });
        let peers = Peers::new();
        let now = Instant::now();
        let disconnect = Alert::PeerDisconnected {
            peer_id: 1,
            addr: "1.2.3.4:1000".to_string(),
            active_secs: 1,
        };
        assert_eq!(suspicious.on_alert(&disconnect, &peers, now), None);
        assert!(suspicious.hosts.is_empty());
    }
}

#[cfg(test)]
mod loopback_tests {
    use super::*;
    use crate::heuristics::{Peer, NETWORK_ONION};

    fn getaddr_flag(peer_id: u64) -> Alert {
        Alert::RepeatedGetaddr {
            peer_id,
            addr: "127.0.0.1:40000".to_string(),
            count: 2,
            threshold: 1,
        }
    }

    fn nonce_flag(peer_id: u64) -> Alert {
        Alert::SmallPingNonce {
            peer_id,
            addr: "127.0.0.1:40000".to_string(),
            count: 4,
            threshold: 3,
        }
    }

    #[test]
    fn tor_inbound_peers_are_judged_per_connection_and_local_tools_not_at_all() {
        let mut suspicious = SuspiciousPeer::new(SuspiciousPeerArgs {
            suspicious_flags: 2,
            suspicious_window_secs: 60,
        });
        let now = Instant::now();
        let mut peers = Peers::new();
        for (peer_id, network) in [
            (1, NETWORK_ONION),
            (2, NETWORK_ONION),
            (3, NETWORK_UNROUTABLE),
        ] {
            peers.insert(
                peer_id,
                Peer {
                    addr: "127.0.0.1:40000".to_string(),
                    last_seen: now,
                    user_agent: None,
                    network: Some(network),
                },
            );
        }
        // Two different Tor peers with one flag each do not add up
        assert_eq!(suspicious.on_alert(&getaddr_flag(1), &peers, now), None);
        assert_eq!(suspicious.on_alert(&nonce_flag(2), &peers, now), None);
        // The same Tor peer with two flags does
        let verdict = suspicious.on_alert(&nonce_flag(1), &peers, now);
        assert!(
            matches!(&verdict, Some(Alert::SuspiciousPeer { host, .. }) if host == "onion inbound peer 1"),
            "got {verdict:?}"
        );
        // The local tool is ignored
        assert_eq!(suspicious.on_alert(&getaddr_flag(3), &peers, now), None);
        assert_eq!(suspicious.on_alert(&nonce_flag(3), &peers, now), None);
    }
}
