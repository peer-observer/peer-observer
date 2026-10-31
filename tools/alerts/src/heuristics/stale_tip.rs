//! Alerts when the node has not connected a block for a long time.
//!
//! Blocks arrive about every ten minutes on average. Two hours without a block
//! happen roughly a handful of times per year on mainnet. Going longer than that
//! means the node lost its peers, a network split, or the data pipeline
//! feeding this tool broke. The alert fires once per stale period. When the
//! next block connects, a recovery alert reports how long the tip was stale.

use super::{block_connected, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::event::Event;
use std::time::{Duration, Instant};

pub const DEFAULT_STALE_TIP_SECS: u64 = 2 * 60 * 60;

#[derive(clap::Args, Debug, Clone)]
pub struct StaleTipArgs {
    /// Alert when no block has been connected for this many seconds
    #[arg(long, default_value_t = DEFAULT_STALE_TIP_SECS)]
    pub stale_tip_secs: u64,
}

impl Default for StaleTipArgs {
    fn default() -> Self {
        StaleTipArgs {
            stale_tip_secs: DEFAULT_STALE_TIP_SECS,
        }
    }
}

pub struct StaleTip {
    threshold: Duration,
    /// When the last block connected. Starts at the tool start, so a quiet
    /// node is reported even if no block was ever seen.
    last_block: Instant,
    last_height: Option<i32>,
    /// Set while the tip is reported as stale.
    stale_since: Option<Instant>,
}

impl StaleTip {
    pub fn new(args: StaleTipArgs, started: Instant) -> Self {
        StaleTip {
            threshold: Duration::from_secs(args.stale_tip_secs),
            last_block: started,
            last_height: None,
            stale_since: None,
        }
    }
}

impl Heuristic for StaleTip {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(block) = block_connected(event) else {
            return;
        };
        if self.stale_since.take().is_some() {
            out.push(Alert::TipRecovered {
                height: block.height,
                stale_secs: ctx.now.duration_since(self.last_block).as_secs(),
            });
        }
        self.last_block = ctx.now;
        self.last_height = Some(block.height);
    }

    fn on_tick(&mut self, ctx: &Context, out: &mut Vec<Alert>) {
        if self.stale_since.is_some() {
            return;
        }
        let since = ctx.now.duration_since(self.last_block);
        if since <= self.threshold {
            return;
        }
        self.stale_since = Some(ctx.now);
        out.push(Alert::StaleTip {
            since_secs: since.as_secs(),
            threshold_secs: self.threshold.as_secs(),
            last_height: self.last_height,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::block;
    use crate::heuristics::Peers;

    fn ctx(peers: &Peers, now: Instant) -> Context<'_> {
        Context { now, peers }
    }

    #[test]
    fn stale_tip_is_reported_once_and_recovery_once() {
        let peers = Peers::new();
        let t0 = Instant::now();
        let mut heuristic = StaleTip::new(
            StaleTipArgs {
                stale_tip_secs: 100,
            },
            t0,
        );
        let mut out = Vec::new();

        heuristic.on_event(
            &block(1, 0),
            &ctx(&peers, t0 + Duration::from_secs(10)),
            &mut out,
        );
        heuristic.on_tick(&ctx(&peers, t0 + Duration::from_secs(110)), &mut out);
        assert!(out.is_empty(), "100s after the last block is not yet stale");

        heuristic.on_tick(&ctx(&peers, t0 + Duration::from_secs(111)), &mut out);
        heuristic.on_tick(&ctx(&peers, t0 + Duration::from_secs(500)), &mut out);
        assert_eq!(
            out,
            vec![Alert::StaleTip {
                since_secs: 101,
                threshold_secs: 100,
                last_height: Some(1),
            }]
        );

        out.clear();
        heuristic.on_event(
            &block(2, 0),
            &ctx(&peers, t0 + Duration::from_secs(600)),
            &mut out,
        );
        heuristic.on_event(
            &block(3, 0),
            &ctx(&peers, t0 + Duration::from_secs(601)),
            &mut out,
        );
        assert_eq!(
            out,
            vec![Alert::TipRecovered {
                height: 2,
                stale_secs: 590,
            }]
        );

        out.clear();
        heuristic.on_tick(&ctx(&peers, t0 + Duration::from_secs(650)), &mut out);
        assert!(out.is_empty(), "the clock restarts with the new block");
    }

    #[test]
    fn a_node_without_any_block_is_reported_with_unknown_height() {
        let peers = Peers::new();
        let t0 = Instant::now();
        let mut heuristic = StaleTip::new(StaleTipArgs { stale_tip_secs: 5 }, t0);
        let mut out = Vec::new();
        heuristic.on_tick(&ctx(&peers, t0 + Duration::from_secs(6)), &mut out);
        assert_eq!(
            out,
            vec![Alert::StaleTip {
                since_secs: 6,
                threshold_secs: 5,
                last_height: None,
            }]
        );
    }
}
