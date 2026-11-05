//! Alerts on address crawlers: connections that ask for addresses and leave.
//!
//! An address crawler connects, finishes the handshake, sends `getaddr`,
//! collects the answer, and disconnects within seconds. One such connection
//! is nothing to report, and the demo node sees several per minute. A
//! netgroup doing it over and over is a crawler worth knowing about, so the
//! heuristic counts these connections per netgroup and reports once per
//! episode when a group passes the threshold.

use super::{
    connection_event, inbound_message, is_loopback, netgroup_of, Context, Heuristic,
    ThresholdWindow, NETWORK_ONION,
};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const DEFAULT_HARVESTER_THRESHOLD: usize = 3;
pub const DEFAULT_HARVESTER_WINDOW_SECS: u64 = 600;
pub const DEFAULT_HARVESTER_MAX_AGE_SECS: u64 = 30;
pub const DEFAULT_HARVESTER_REPEAT_SECS: u64 = 3600;

#[derive(clap::Args, Debug, Clone)]
pub struct AddressHarvesterArgs {
    /// Number of short connections asking for addresses from one netgroup before alerting
    #[arg(long, default_value_t = DEFAULT_HARVESTER_THRESHOLD)]
    pub harvester_threshold: usize,

    /// Sliding window size for address harvester detection (seconds)
    #[arg(long, default_value_t = DEFAULT_HARVESTER_WINDOW_SECS)]
    pub harvester_window_secs: u64,

    /// A connection that asked for addresses counts as harvesting if it closed within this many seconds
    #[arg(long, default_value_t = DEFAULT_HARVESTER_MAX_AGE_SECS)]
    pub harvester_max_age_secs: u64,

    /// Report a netgroup that keeps harvesting at most once per this many seconds
    #[arg(long, default_value_t = DEFAULT_HARVESTER_REPEAT_SECS)]
    pub harvester_repeat_secs: u64,
}

impl Default for AddressHarvesterArgs {
    fn default() -> Self {
        AddressHarvesterArgs {
            harvester_threshold: DEFAULT_HARVESTER_THRESHOLD,
            harvester_window_secs: DEFAULT_HARVESTER_WINDOW_SECS,
            harvester_max_age_secs: DEFAULT_HARVESTER_MAX_AGE_SECS,
            harvester_repeat_secs: DEFAULT_HARVESTER_REPEAT_SECS,
        }
    }
}

pub struct AddressHarvester {
    args: AddressHarvesterArgs,
    /// Peers that sent us a getaddr on their current connection.
    asked: HashSet<u64>,
    /// Short address-collecting connections per netgroup.
    groups: HashMap<String, ThresholdWindow>,
}

impl AddressHarvester {
    pub fn new(args: AddressHarvesterArgs) -> Self {
        AddressHarvester {
            args,
            asked: HashSet::new(),
            groups: HashMap::new(),
        }
    }
}

impl Heuristic for AddressHarvester {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        if let Some(msg) = inbound_message(event) {
            if matches!(msg.msg, Some(Msg::Getaddr(_))) {
                self.asked.insert(msg.meta.peer_id);
            }
            return;
        }
        let Some(ConnectionEvent::Closed(closed)) = connection_event(event) else {
            return;
        };
        if !self.asked.remove(&closed.conn.peer_id) || closed.time_established == 0 {
            return;
        }
        let closed_at = event.timestamp / 1000;
        let age = closed_at.saturating_sub(closed.time_established);
        if age > self.args.harvester_max_age_secs {
            return;
        }
        // Inbound Tor connections all arrive from localhost. They cannot be
        // told apart, so they count as one group. Local tools are left out.
        let netgroup = if is_loopback(&closed.conn.addr) {
            if closed.conn.network != NETWORK_ONION {
                return;
            }
            "onion inbound".to_string()
        } else {
            netgroup_of(&closed.conn.addr)
        };
        let window = Duration::from_secs(self.args.harvester_window_secs);
        let threshold = self.args.harvester_threshold;
        let group = self.groups.entry(netgroup.clone()).or_insert_with(|| {
            ThresholdWindow::with_repeat(
                window,
                threshold,
                Duration::from_secs(self.args.harvester_repeat_secs),
            )
        });
        if let Some(count) = group.record(ctx.now) {
            out.push(Alert::AddressHarvester {
                netgroup,
                count,
                window_secs: self.args.harvester_window_secs,
                threshold,
                max_age_secs: self.args.harvester_max_age_secs,
            });
        }
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        self.groups.retain(|_, group| {
            group.tick(ctx.now);
            !group.is_idle(ctx.now)
        });
    }

    fn on_peer_removed(&mut self, peer_id: u64) -> Option<Instant> {
        self.asked.remove(&peer_id);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{closed, message, EVENT_TIMESTAMP_SECS};
    use crate::heuristics::Peers;
    use shared::protobuf::bitcoin_primitives::ConnType;

    fn getaddr(peer_id: u64) -> Event {
        message(peer_id, true, "getaddr", Msg::Getaddr(true))
    }

    fn run(heuristic: &mut AddressHarvester, events: &[Event]) -> Vec<Alert> {
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        for event in events {
            heuristic.on_event(event, &ctx, &mut out);
        }
        out
    }

    #[test]
    fn short_getaddr_connections_from_one_group_alert_once() {
        let mut heuristic = AddressHarvester::new(AddressHarvesterArgs {
            harvester_threshold: 2,
            harvester_window_secs: 60,
            harvester_max_age_secs: 30,
            harvester_repeat_secs: 60,
        });
        let young = EVENT_TIMESTAMP_SECS - 5;
        let old = EVENT_TIMESTAMP_SECS - 600;
        let events = [
            getaddr(1),
            closed(1, ConnType::Inbound, young),
            // Left without asking: not a harvester
            closed(2, ConnType::Inbound, young),
            // Asked but stayed for ten minutes: a normal node
            getaddr(3),
            closed(3, ConnType::Inbound, old),
            getaddr(4),
            closed(4, ConnType::Inbound, young),
            getaddr(5),
            closed(5, ConnType::Inbound, young),
            getaddr(6),
            closed(6, ConnType::Inbound, young),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::AddressHarvester {
                netgroup: "1.2.0.0/16".to_string(),
                count: 3,
                window_secs: 60,
                threshold: 2,
                max_age_secs: 30,
            }]
        );
        assert!(heuristic.asked.is_empty());
    }

    #[test]
    fn tor_inbound_counts_as_one_group_and_local_tools_do_not_count() {
        use crate::heuristics::test_util::connection;
        use crate::heuristics::{NETWORK_ONION, NETWORK_UNROUTABLE};
        use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
        use shared::protobuf::ebpf_extractor::connection::{ClosedConnection, Connection};

        let closed_local = |peer_id: u64, network: u32| {
            connection(ConnectionEvent::Closed(ClosedConnection {
                conn: Connection {
                    peer_id,
                    addr: format!("127.0.0.1:{}", 40000 + peer_id),
                    conn_type: ConnType::Inbound as i32,
                    network,
                },
                time_established: EVENT_TIMESTAMP_SECS - 5,
            }))
        };
        let mut heuristic = AddressHarvester::new(AddressHarvesterArgs {
            harvester_threshold: 1,
            harvester_window_secs: 60,
            harvester_max_age_secs: 30,
            harvester_repeat_secs: 60,
        });
        let events = [
            getaddr(1),
            closed_local(1, NETWORK_UNROUTABLE),
            getaddr(2),
            closed_local(2, NETWORK_UNROUTABLE),
            getaddr(3),
            closed_local(3, NETWORK_ONION),
            getaddr(4),
            closed_local(4, NETWORK_ONION),
        ];
        let alerts = run(&mut heuristic, &events);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(
            &alerts[0],
            Alert::AddressHarvester { netgroup, count: 2, .. } if netgroup == "onion inbound"
        ));
    }

    #[test]
    fn a_busy_group_is_reported_once_per_window() {
        let mut heuristic = AddressHarvester::new(AddressHarvesterArgs {
            harvester_threshold: 1,
            harvester_window_secs: 60,
            harvester_max_age_secs: 30,
            harvester_repeat_secs: 60,
        });
        let peers = Peers::new();
        let t0 = Instant::now();
        let mut out = Vec::new();
        let young = EVENT_TIMESTAMP_SECS - 5;
        // Two connections report the group, then the hits age out of the
        // window and two more arrive: still inside the report cooldown
        for (peer_id, secs) in [(1, 0), (2, 1), (3, 40), (4, 41)] {
            let ctx = Context {
                now: t0 + Duration::from_secs(secs),
                peers: &peers,
            };
            heuristic.on_tick(&ctx, &mut out);
            heuristic.on_event(&getaddr(peer_id), &ctx, &mut out);
            heuristic.on_event(&closed(peer_id, ConnType::Inbound, young), &ctx, &mut out);
        }
        assert_eq!(out.len(), 1);
        // A full window later the group can be reported again
        for (peer_id, secs) in [(5, 120), (6, 121)] {
            let ctx = Context {
                now: t0 + Duration::from_secs(secs),
                peers: &peers,
            };
            heuristic.on_tick(&ctx, &mut out);
            heuristic.on_event(&getaddr(peer_id), &ctx, &mut out);
            heuristic.on_event(&closed(peer_id, ConnType::Inbound, young), &ctx, &mut out);
        }
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn idle_groups_are_forgotten() {
        let mut heuristic = AddressHarvester::new(AddressHarvesterArgs {
            harvester_threshold: 5,
            harvester_window_secs: 60,
            harvester_max_age_secs: 30,
            harvester_repeat_secs: 60,
        });
        let peers = Peers::new();
        let t0 = Instant::now();
        let ctx = Context {
            now: t0,
            peers: &peers,
        };
        let mut out = Vec::new();
        heuristic.on_event(&getaddr(1), &ctx, &mut out);
        heuristic.on_event(
            &closed(1, ConnType::Inbound, EVENT_TIMESTAMP_SECS - 1),
            &ctx,
            &mut out,
        );
        assert_eq!(heuristic.groups.len(), 1);
        heuristic.on_tick(
            &Context {
                now: t0 + Duration::from_secs(61),
                peers: &peers,
            },
            &mut out,
        );
        assert!(heuristic.groups.is_empty());
    }
}
