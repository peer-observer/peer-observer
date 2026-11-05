//! Alerts when several long-lived connections close within a short time.
//!
//! Connections that have been up for a day or longer are the stable part of
//! a node's peer set: well-connected nodes and our own outbound peers. Losing
//! several of them at once is unusual and points at network trouble, a peer
//! operator restarting many nodes, or someone cycling connections to us. The
//! connection age comes from the time the connection was established, which
//! Bitcoin Core reports when it closes the connection.

use super::{connection_event, Context, Heuristic, ThresholdWindow};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;
use std::time::Duration;

pub const DEFAULT_OLD_CONNECTION_DROP_THRESHOLD: usize = 5;
pub const DEFAULT_OLD_CONNECTION_DROP_WINDOW_SECS: u64 = 300;
pub const DEFAULT_OLD_CONNECTION_AGE_SECS: u64 = 24 * 60 * 60;

#[derive(clap::Args, Debug, Clone)]
pub struct OldConnectionDropsArgs {
    /// Number of old connections closed in the window before alerting
    #[arg(long, default_value_t = DEFAULT_OLD_CONNECTION_DROP_THRESHOLD)]
    pub old_connection_drop_threshold: usize,

    /// Sliding window size for old connection drops (seconds)
    #[arg(long, default_value_t = DEFAULT_OLD_CONNECTION_DROP_WINDOW_SECS)]
    pub old_connection_drop_window_secs: u64,

    /// A connection counts as old once it has been up for this many seconds
    #[arg(long, default_value_t = DEFAULT_OLD_CONNECTION_AGE_SECS)]
    pub old_connection_age_secs: u64,
}

impl Default for OldConnectionDropsArgs {
    fn default() -> Self {
        OldConnectionDropsArgs {
            old_connection_drop_threshold: DEFAULT_OLD_CONNECTION_DROP_THRESHOLD,
            old_connection_drop_window_secs: DEFAULT_OLD_CONNECTION_DROP_WINDOW_SECS,
            old_connection_age_secs: DEFAULT_OLD_CONNECTION_AGE_SECS,
        }
    }
}

pub struct OldConnectionDrops {
    args: OldConnectionDropsArgs,
    drops: ThresholdWindow,
}

impl OldConnectionDrops {
    pub fn new(args: OldConnectionDropsArgs) -> Self {
        let window = Duration::from_secs(args.old_connection_drop_window_secs);
        OldConnectionDrops {
            drops: ThresholdWindow::new(window, args.old_connection_drop_threshold),
            args,
        }
    }
}

impl Heuristic for OldConnectionDrops {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(ConnectionEvent::Closed(closed)) = connection_event(event) else {
            return;
        };
        // Zero means Bitcoin Core did not know when the connection was
        // established, so its age is unknown.
        if closed.time_established == 0 {
            return;
        }
        let closed_at = event.timestamp / 1000;
        let age = closed_at.saturating_sub(closed.time_established);
        if age < self.args.old_connection_age_secs {
            return;
        }
        if let Some(count) = self.drops.record(ctx.now) {
            out.push(Alert::OldConnectionDrops {
                count,
                window_secs: self.args.old_connection_drop_window_secs,
                threshold: self.args.old_connection_drop_threshold,
                min_age_secs: self.args.old_connection_age_secs,
            });
        }
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        self.drops.tick(ctx.now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{closed, EVENT_TIMESTAMP_SECS};
    use crate::heuristics::Peers;
    use shared::protobuf::bitcoin_primitives::ConnType;
    use std::time::Instant;

    const DAY: u64 = 24 * 60 * 60;

    fn args(threshold: usize) -> OldConnectionDropsArgs {
        OldConnectionDropsArgs {
            old_connection_drop_threshold: threshold,
            old_connection_drop_window_secs: 60,
            old_connection_age_secs: DAY,
        }
    }

    fn run(heuristic: &mut OldConnectionDrops, events: &[Event]) -> Vec<Alert> {
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
    fn old_connections_of_any_type_count() {
        let mut heuristic = OldConnectionDrops::new(args(2));
        let two_days_ago = EVENT_TIMESTAMP_SECS - 2 * DAY;
        let events = [
            closed(1, ConnType::Inbound, two_days_ago),
            closed(2, ConnType::OutboundFullRelay, two_days_ago),
            closed(3, ConnType::BlockRelayOnly, EVENT_TIMESTAMP_SECS - DAY),
            closed(4, ConnType::Inbound, two_days_ago),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::OldConnectionDrops {
                count: 3,
                window_secs: 60,
                threshold: 2,
                min_age_secs: DAY,
            }]
        );
    }

    #[test]
    fn young_and_unknown_age_connections_do_not_count() {
        let mut heuristic = OldConnectionDrops::new(args(0));
        let events = [
            closed(1, ConnType::Inbound, EVENT_TIMESTAMP_SECS - DAY + 1),
            closed(2, ConnType::Inbound, EVENT_TIMESTAMP_SECS),
            closed(3, ConnType::Inbound, 0),
        ];
        assert!(run(&mut heuristic, &events).is_empty());
    }
}
