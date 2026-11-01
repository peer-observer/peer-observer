//! Alerts when several peers misbehave in the same way over a longer time.
//!
//! `MisbehavingBurst` catches many reports within minutes. A slower pattern
//! slips through it: in a seven-hour live run seven different peers, claiming
//! three different user agents, each sent headers with invalid proof of work,
//! spaced 20 to 60 minutes apart. One peer doing that is a broken node. Several
//! peers with the same reason over hours share software, a bad upstream, or an
//! operator. This heuristic counts the distinct peers per reason over a long
//! window and reports a reason once per window.

use super::{connection_event, host_of, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const DEFAULT_MISBEHAVING_PATTERN_PEERS: usize = 2;
pub const DEFAULT_MISBEHAVING_PATTERN_WINDOW_SECS: u64 = 6 * 60 * 60;

#[derive(clap::Args, Debug, Clone)]
pub struct MisbehavingPatternArgs {
    /// Number of different peers reported for the same reason in the window before alerting
    #[arg(long, default_value_t = DEFAULT_MISBEHAVING_PATTERN_PEERS)]
    pub misbehaving_pattern_peers: usize,

    /// Sliding window size for misbehaving patterns (seconds)
    #[arg(long, default_value_t = DEFAULT_MISBEHAVING_PATTERN_WINDOW_SECS)]
    pub misbehaving_pattern_window_secs: u64,
}

impl Default for MisbehavingPatternArgs {
    fn default() -> Self {
        MisbehavingPatternArgs {
            misbehaving_pattern_peers: DEFAULT_MISBEHAVING_PATTERN_PEERS,
            misbehaving_pattern_window_secs: DEFAULT_MISBEHAVING_PATTERN_WINDOW_SECS,
        }
    }
}

#[derive(Default)]
struct Reason {
    /// Which host was reported when, oldest first.
    reports: VecDeque<(String, Instant)>,
    reported_at: Option<Instant>,
}

pub struct MisbehavingPattern {
    args: MisbehavingPatternArgs,
    reasons: HashMap<String, Reason>,
}

impl MisbehavingPattern {
    pub fn new(args: MisbehavingPatternArgs) -> Self {
        MisbehavingPattern {
            args,
            reasons: HashMap::new(),
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.args.misbehaving_pattern_window_secs)
    }
}

impl Heuristic for MisbehavingPattern {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(ConnectionEvent::Misbehaving(misbehaving)) = connection_event(event) else {
            return;
        };
        // Count by host so a peer that reconnects is one peer. Peers whose
        // address we never saw are counted by id.
        let host = match ctx.peers.get(&misbehaving.id) {
            Some(peer) => host_of(&peer.addr).to_string(),
            None => format!("peer {}", misbehaving.id),
        };
        let window = self.window();
        let threshold = self.args.misbehaving_pattern_peers;
        let reason = self.reasons.entry(misbehaving.message.clone()).or_default();
        reason.reports.push_back((host, ctx.now));
        while reason
            .reports
            .front()
            .is_some_and(|(_, at)| ctx.now.duration_since(*at) > window)
        {
            reason.reports.pop_front();
        }
        let peers: HashSet<&str> = reason.reports.iter().map(|(h, _)| h.as_str()).collect();
        if peers.len() <= threshold {
            return;
        }
        if reason
            .reported_at
            .is_some_and(|at| ctx.now.duration_since(at) < window)
        {
            return;
        }
        reason.reported_at = Some(ctx.now);
        out.push(Alert::MisbehavingPattern {
            reason: misbehaving.message.clone(),
            peers: peers.len(),
            window_secs: self.args.misbehaving_pattern_window_secs,
            threshold,
        });
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        let window = self.window();
        self.reasons.retain(|_, reason| {
            while reason
                .reports
                .front()
                .is_some_and(|(_, at)| ctx.now.duration_since(*at) > window)
            {
                reason.reports.pop_front();
            }
            !reason.reports.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::connection;
    use crate::heuristics::{Peer, Peers};
    use shared::protobuf::ebpf_extractor::connection::MisbehavingConnection;

    fn misbehaving(peer_id: u64, reason: &str) -> Event {
        connection(ConnectionEvent::Misbehaving(MisbehavingConnection {
            id: peer_id,
            message: reason.to_string(),
        }))
    }

    fn peers_at(addrs: &[(u64, &str)], now: Instant) -> Peers {
        let mut peers = Peers::new();
        for (id, addr) in addrs {
            peers.insert(
                *id,
                Peer {
                    addr: addr.to_string(),
                    last_seen: now,
                    user_agent: None,
                    network: None,
                },
            );
        }
        peers
    }

    #[test]
    fn the_same_reason_from_several_hosts_is_reported_once_per_window() {
        let t0 = Instant::now();
        let peers = peers_at(
            &[
                (1, "1.1.1.1:1000"),
                (2, "1.1.1.1:1001"),
                (3, "2.2.2.2:1000"),
                (4, "3.3.3.3:1000"),
                (5, "4.4.4.4:1000"),
            ],
            t0,
        );
        let mut heuristic = MisbehavingPattern::new(MisbehavingPatternArgs {
            misbehaving_pattern_peers: 2,
            misbehaving_pattern_window_secs: 3600,
        });
        let mut out = Vec::new();
        let at = |s: u64| Context {
            now: t0 + Duration::from_secs(s),
            peers: &peers,
        };
        // Two reports from one host are one peer, a different reason is apart
        heuristic.on_event(&misbehaving(1, "bad header"), &at(0), &mut out);
        heuristic.on_event(&misbehaving(2, "bad header"), &at(600), &mut out);
        heuristic.on_event(&misbehaving(3, "bad header"), &at(1200), &mut out);
        heuristic.on_event(&misbehaving(4, "bad getdata"), &at(1300), &mut out);
        assert!(out.is_empty());
        heuristic.on_event(&misbehaving(4, "bad header"), &at(1800), &mut out);
        assert_eq!(
            out,
            vec![Alert::MisbehavingPattern {
                reason: "bad header".to_string(),
                peers: 3,
                window_secs: 3600,
                threshold: 2,
            }]
        );
        // More of the same inside the window is not reported again
        heuristic.on_event(&misbehaving(5, "bad header"), &at(2400), &mut out);
        assert_eq!(out.len(), 1);
        // Reports age out of the window, and the state with them
        heuristic.on_tick(&at(10_000), &mut out);
        assert!(heuristic.reasons.is_empty());
    }
}
