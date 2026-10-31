//! Alerts when the node has fewer outbound peers than it should.
//!
//! Bitcoin Core keeps eight full-relay outbound connections and replaces a
//! lost one on its own. Finding a new peer can take a while: a dip to seven
//! for half a minute is normal. Staying below the target for minutes means
//! the node cannot find or reach peers: the network is down, the addrman is
//! poisoned, or something blocks outbound connections. Outbound peers are
//! the ones we chose ourselves, so losing them also makes the node easier to
//! eclipse.

use super::{peer_infos, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::event::Event;
use std::time::{Duration, Instant};

/// Bitcoin Core's default number of full-relay outbound connections.
pub const DEFAULT_MIN_OUTBOUND_PEERS: usize = 8;
pub const DEFAULT_LOW_OUTBOUND_SECS: u64 = 120;

/// The connection type `getpeerinfo` reports for full-relay outbound peers.
const OUTBOUND_FULL_RELAY: &str = "outbound-full-relay";

#[derive(clap::Args, Debug, Clone)]
pub struct LowOutboundPeersArgs {
    /// Alert when fewer than this many full-relay outbound peers are connected
    #[arg(long, default_value_t = DEFAULT_MIN_OUTBOUND_PEERS)]
    pub min_outbound_peers: usize,

    /// Only alert once the outbound peer count has been low for this many seconds
    #[arg(long, default_value_t = DEFAULT_LOW_OUTBOUND_SECS)]
    pub low_outbound_secs: u64,
}

impl Default for LowOutboundPeersArgs {
    fn default() -> Self {
        LowOutboundPeersArgs {
            min_outbound_peers: DEFAULT_MIN_OUTBOUND_PEERS,
            low_outbound_secs: DEFAULT_LOW_OUTBOUND_SECS,
        }
    }
}

pub struct LowOutboundPeers {
    args: LowOutboundPeersArgs,
    /// When the count first fell below the threshold, while it stays below.
    below_since: Option<Instant>,
    /// False while an episode is being reported.
    armed: bool,
}

impl LowOutboundPeers {
    pub fn new(args: LowOutboundPeersArgs) -> Self {
        LowOutboundPeers {
            args,
            below_since: None,
            armed: true,
        }
    }
}

impl Heuristic for LowOutboundPeers {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(infos) = peer_infos(event) else {
            return;
        };
        let outbound = infos
            .infos
            .iter()
            .filter(|peer| peer.connection_type == OUTBOUND_FULL_RELAY)
            .count();
        if outbound >= self.args.min_outbound_peers {
            self.below_since = None;
            self.armed = true;
            return;
        }
        let below_since = *self.below_since.get_or_insert(ctx.now);
        let below_for = ctx.now.duration_since(below_since);
        if below_for < Duration::from_secs(self.args.low_outbound_secs) || !self.armed {
            return;
        }
        self.armed = false;
        out.push(Alert::LowOutboundPeers {
            outbound,
            threshold: self.args.min_outbound_peers,
            below_for_secs: below_for.as_secs(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{peer_info, peer_infos_event};
    use crate::heuristics::Peers;

    fn poll(outbound: usize, inbound: usize, block_relay: usize) -> Event {
        let mut infos = Vec::new();
        let mut id = 0;
        for (count, kind) in [
            (outbound, OUTBOUND_FULL_RELAY),
            (inbound, "inbound"),
            (block_relay, "block-relay-only"),
        ] {
            for _ in 0..count {
                infos.push(peer_info(id, kind, 0.0));
                id += 1;
            }
        }
        peer_infos_event(infos)
    }

    fn run_at(heuristic: &mut LowOutboundPeers, events: &[(Event, u64)]) -> Vec<Alert> {
        let peers = Peers::new();
        let t0 = Instant::now();
        let mut out = Vec::new();
        for (event, secs) in events {
            let ctx = Context {
                now: t0 + Duration::from_secs(*secs),
                peers: &peers,
            };
            heuristic.on_event(event, &ctx, &mut out);
        }
        out
    }

    #[test]
    fn a_long_dip_alerts_once_until_recovered() {
        let mut heuristic = LowOutboundPeers::new(LowOutboundPeersArgs {
            min_outbound_peers: 8,
            low_outbound_secs: 60,
        });
        let events = [
            (poll(8, 20, 2), 0),
            // A short dip is a connection being replaced
            (poll(7, 20, 2), 10),
            (poll(8, 20, 2), 20),
            // Inbound and block-relay-only peers do not count
            (poll(3, 50, 2), 30),
            (poll(2, 50, 2), 60),
            (poll(1, 50, 2), 90),
            (poll(0, 50, 2), 120),
            (poll(8, 50, 2), 130),
            (poll(0, 0, 0), 140),
            (poll(0, 0, 0), 199),
            (poll(0, 0, 0), 200),
        ];
        assert_eq!(
            run_at(&mut heuristic, &events),
            vec![
                Alert::LowOutboundPeers {
                    outbound: 1,
                    threshold: 8,
                    below_for_secs: 60,
                },
                Alert::LowOutboundPeers {
                    outbound: 0,
                    threshold: 8,
                    below_for_secs: 60,
                },
            ]
        );
    }
}
