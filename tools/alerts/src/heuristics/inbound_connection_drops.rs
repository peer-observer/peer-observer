//! Alerts when many established inbound connections close within a short
//! time.
//!
//! Inbound peers come and go. On a reachable node most inbound connections
//! are crawlers that leave within seconds, so those are ignored and only
//! connections that lived for a while count. Many of those leaving at once
//! points at a problem: the node became unreachable, a provider has network
//! trouble, or a group of peers controlled by one party left together.
//! Connections that Bitcoin Core evicted itself are not counted either. Core
//! only evicts when its inbound slots are full, and those drops are routine.

use super::{connection_event, Context, Heuristic, ThresholdWindow};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::bitcoin_primitives::ConnType;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_INBOUND_DROP_THRESHOLD: usize = 20;
pub const DEFAULT_INBOUND_DROP_WINDOW_SECS: u64 = 300;
pub const DEFAULT_INBOUND_DROP_MIN_AGE_SECS: u64 = 60;

#[derive(clap::Args, Debug, Clone)]
pub struct InboundConnectionDropsArgs {
    /// Number of inbound connections closed in the window before alerting
    #[arg(long, default_value_t = DEFAULT_INBOUND_DROP_THRESHOLD)]
    pub inbound_drop_threshold: usize,

    /// Sliding window size for inbound connection drops (seconds)
    #[arg(long, default_value_t = DEFAULT_INBOUND_DROP_WINDOW_SECS)]
    pub inbound_drop_window_secs: u64,

    /// Only count closed inbound connections that were up for at least this many seconds
    #[arg(long, default_value_t = DEFAULT_INBOUND_DROP_MIN_AGE_SECS)]
    pub inbound_drop_min_age_secs: u64,
}

impl Default for InboundConnectionDropsArgs {
    fn default() -> Self {
        InboundConnectionDropsArgs {
            inbound_drop_threshold: DEFAULT_INBOUND_DROP_THRESHOLD,
            inbound_drop_window_secs: DEFAULT_INBOUND_DROP_WINDOW_SECS,
            inbound_drop_min_age_secs: DEFAULT_INBOUND_DROP_MIN_AGE_SECS,
        }
    }
}

pub struct InboundConnectionDrops {
    args: InboundConnectionDropsArgs,
    drops: ThresholdWindow,
    /// Peers Bitcoin Core evicted, and when. Their connection closes right
    /// after and must not count as a drop. Entries are forgotten after the
    /// window in case the close event never shows up.
    evicted: HashMap<u64, Instant>,
}

impl InboundConnectionDrops {
    pub fn new(args: InboundConnectionDropsArgs) -> Self {
        let window = Duration::from_secs(args.inbound_drop_window_secs);
        InboundConnectionDrops {
            drops: ThresholdWindow::new(window, args.inbound_drop_threshold),
            evicted: HashMap::new(),
            args,
        }
    }

    fn window(&self) -> Duration {
        Duration::from_secs(self.args.inbound_drop_window_secs)
    }
}

impl Heuristic for InboundConnectionDrops {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        match connection_event(event) {
            Some(ConnectionEvent::InboundEvicted(evicted)) => {
                self.evicted.insert(evicted.conn.peer_id, ctx.now);
            }
            Some(ConnectionEvent::Closed(closed)) => {
                if closed.conn.conn_type != ConnType::Inbound as i32 {
                    return;
                }
                if self.evicted.remove(&closed.conn.peer_id).is_some() {
                    return;
                }
                // Zero means Bitcoin Core did not know when the connection
                // was established, so its age is unknown.
                if closed.time_established == 0 {
                    return;
                }
                let closed_at = event.timestamp / 1000;
                let age = closed_at.saturating_sub(closed.time_established);
                if age < self.args.inbound_drop_min_age_secs {
                    return;
                }
                if let Some(count) = self.drops.record(ctx.now) {
                    out.push(Alert::InboundConnectionDrops {
                        count,
                        window_secs: self.args.inbound_drop_window_secs,
                        threshold: self.args.inbound_drop_threshold,
                        min_age_secs: self.args.inbound_drop_min_age_secs,
                    });
                }
            }
            _ => {}
        }
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        self.drops.tick(ctx.now);
        let window = self.window();
        self.evicted
            .retain(|_, evicted_at| ctx.now.duration_since(*evicted_at) <= window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{closed, evicted, EVENT_TIMESTAMP_SECS};
    use crate::heuristics::Peers;

    /// Established two minutes before the test events are seen.
    const ESTABLISHED: u64 = EVENT_TIMESTAMP_SECS - 120;

    fn args(threshold: usize) -> InboundConnectionDropsArgs {
        InboundConnectionDropsArgs {
            inbound_drop_threshold: threshold,
            inbound_drop_window_secs: 60,
            inbound_drop_min_age_secs: 60,
        }
    }

    fn run(heuristic: &mut InboundConnectionDrops, events: &[Event]) -> Vec<Alert> {
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
    fn many_inbound_drops_alert_once() {
        let mut heuristic = InboundConnectionDrops::new(args(2));
        let events = [
            closed(1, ConnType::Inbound, ESTABLISHED),
            closed(2, ConnType::Inbound, ESTABLISHED),
            closed(3, ConnType::Inbound, ESTABLISHED),
            closed(4, ConnType::Inbound, ESTABLISHED),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::InboundConnectionDrops {
                count: 3,
                window_secs: 60,
                threshold: 2,
                min_age_secs: 60,
            }]
        );
    }

    #[test]
    fn young_evicted_and_outbound_connections_do_not_count() {
        let mut heuristic = InboundConnectionDrops::new(args(1));
        let events = [
            evicted(1),
            closed(1, ConnType::Inbound, ESTABLISHED),
            closed(2, ConnType::OutboundFullRelay, ESTABLISHED),
            closed(3, ConnType::BlockRelayOnly, ESTABLISHED),
            // A crawler that left after two seconds
            closed(4, ConnType::Inbound, EVENT_TIMESTAMP_SECS - 2),
            // Age unknown
            closed(5, ConnType::Inbound, 0),
            closed(6, ConnType::Inbound, ESTABLISHED),
        ];
        assert!(run(&mut heuristic, &events).is_empty());
        assert!(
            heuristic.evicted.is_empty(),
            "the eviction is forgotten once the connection closed"
        );
    }

    #[test]
    fn forgotten_evictions_expire_with_the_window() {
        let mut heuristic = InboundConnectionDrops::new(args(1));
        let peers = Peers::new();
        let t0 = Instant::now();
        let ctx = Context {
            now: t0,
            peers: &peers,
        };
        heuristic.on_event(&evicted(1), &ctx, &mut Vec::new());
        heuristic.on_tick(
            &Context {
                now: t0 + Duration::from_secs(61),
                peers: &peers,
            },
            &mut Vec::new(),
        );
        assert!(heuristic.evicted.is_empty());
    }
}
