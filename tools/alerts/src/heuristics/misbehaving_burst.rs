//! Alerts when Bitcoin Core reports many misbehaving peers in a short time.
//!
//! A single misbehaving peer is a single bad actor or a bug, and the
//! `MisbehavingPeer` heuristic reports each one. Many reports within minutes
//! point at something bigger: a coordinated set of peers, a client release
//! with a bug, or a change on our side that makes us reject peers.

use super::{connection_event, Context, Heuristic, ThresholdWindow};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;
use std::time::Duration;

pub const DEFAULT_MISBEHAVING_BURST_THRESHOLD: usize = 5;
pub const DEFAULT_MISBEHAVING_BURST_WINDOW_SECS: u64 = 600;

#[derive(clap::Args, Debug, Clone)]
pub struct MisbehavingBurstArgs {
    /// Number of misbehaving reports in the window before alerting
    #[arg(long, default_value_t = DEFAULT_MISBEHAVING_BURST_THRESHOLD)]
    pub misbehaving_burst_threshold: usize,

    /// Sliding window size for misbehaving reports (seconds)
    #[arg(long, default_value_t = DEFAULT_MISBEHAVING_BURST_WINDOW_SECS)]
    pub misbehaving_burst_window_secs: u64,
}

impl Default for MisbehavingBurstArgs {
    fn default() -> Self {
        MisbehavingBurstArgs {
            misbehaving_burst_threshold: DEFAULT_MISBEHAVING_BURST_THRESHOLD,
            misbehaving_burst_window_secs: DEFAULT_MISBEHAVING_BURST_WINDOW_SECS,
        }
    }
}

pub struct MisbehavingBurst {
    args: MisbehavingBurstArgs,
    reports: ThresholdWindow,
}

impl MisbehavingBurst {
    pub fn new(args: MisbehavingBurstArgs) -> Self {
        let window = Duration::from_secs(args.misbehaving_burst_window_secs);
        MisbehavingBurst {
            reports: ThresholdWindow::new(window, args.misbehaving_burst_threshold),
            args,
        }
    }
}

impl Heuristic for MisbehavingBurst {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(ConnectionEvent::Misbehaving(_)) = connection_event(event) else {
            return;
        };
        if let Some(count) = self.reports.record(ctx.now) {
            out.push(Alert::MisbehavingBurst {
                count,
                window_secs: self.args.misbehaving_burst_window_secs,
                threshold: self.args.misbehaving_burst_threshold,
            });
        }
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        self.reports.tick(ctx.now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::connection;
    use crate::heuristics::Peers;
    use shared::protobuf::ebpf_extractor::connection::MisbehavingConnection;
    use std::time::Instant;

    fn misbehaving(peer_id: u64) -> Event {
        connection(ConnectionEvent::Misbehaving(MisbehavingConnection {
            id: peer_id,
            message: "bad".to_string(),
        }))
    }

    #[test]
    fn a_burst_alerts_once_per_episode() {
        let mut heuristic = MisbehavingBurst::new(MisbehavingBurstArgs {
            misbehaving_burst_threshold: 2,
            misbehaving_burst_window_secs: 60,
        });
        let peers = Peers::new();
        let t0 = Instant::now();
        let ctx = Context {
            now: t0,
            peers: &peers,
        };
        let mut out = Vec::new();
        for peer_id in 1..=5 {
            heuristic.on_event(&misbehaving(peer_id), &ctx, &mut out);
        }
        assert_eq!(
            out,
            vec![Alert::MisbehavingBurst {
                count: 3,
                window_secs: 60,
                threshold: 2,
            }]
        );

        // After the window passed, the next burst is reported again
        let later = Context {
            now: t0 + Duration::from_secs(120),
            peers: &peers,
        };
        heuristic.on_tick(&later, &mut out);
        out.clear();
        for peer_id in 6..=8 {
            heuristic.on_event(&misbehaving(peer_id), &later, &mut out);
        }
        assert_eq!(out.len(), 1);
    }
}
