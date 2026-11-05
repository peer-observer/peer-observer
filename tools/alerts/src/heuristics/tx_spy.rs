//! Flags peers that take our transaction announcements and never send any.
//!
//! A peer that asked for transaction relay receives our announcements. A
//! normal node also announces the transactions it hears about elsewhere and
//! sends us the ones we request. A peer that stays connected with relay on
//! and never sends a single `inv` or `tx` only listens. That is what
//! monitoring nodes and spy peers look like, and in a live run the two peers
//! with counter ping nonces did exactly this for hours.
//!
//! The check works from `getpeerinfo`, which reports per peer whether we relay
//! transactions to it, when it connected, and how many bytes of each message
//! type it sent. That covers peers connected before the tool started, which a
//! check based on the message stream would miss.

use super::{peer_infos, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::event::Event;
use shared::protobuf::rpc_extractor::PeerInfo;
use std::collections::HashMap;
use std::time::Instant;

pub const DEFAULT_TX_SPY_SECS: u64 = 600;

#[derive(clap::Args, Debug, Clone)]
pub struct TxSpyArgs {
    /// Alert when a peer with transaction relay on has sent no inv or tx after this many seconds
    #[arg(long, default_value_t = DEFAULT_TX_SPY_SECS)]
    pub tx_spy_secs: u64,
}

impl Default for TxSpyArgs {
    fn default() -> Self {
        TxSpyArgs {
            tx_spy_secs: DEFAULT_TX_SPY_SECS,
        }
    }
}

pub struct TxSpy {
    args: TxSpyArgs,
    /// Peers reported so far and when, by peer id.
    reported: HashMap<u64, Instant>,
}

impl TxSpy {
    pub fn new(args: TxSpyArgs) -> Self {
        TxSpy {
            args,
            reported: HashMap::new(),
        }
    }
}

/// True if the peer sent us at least one `inv` or `tx` message.
fn sent_transactions(peer: &PeerInfo) -> bool {
    ["inv", "tx"].iter().any(|command| {
        peer.bytes_received_per_message
            .get(*command)
            .is_some_and(|bytes| *bytes > 0)
    })
}

impl Heuristic for TxSpy {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(infos) = peer_infos(event) else {
            return;
        };
        let now = event.timestamp / 1000;
        // Peers that are gone can be reported again if they come back.
        self.reported
            .retain(|peer_id, _| infos.infos.iter().any(|p| u64::from(p.id) == *peer_id));
        for peer in &infos.infos {
            let peer_id = u64::from(peer.id);
            if !peer.relay_transactions || self.reported.contains_key(&peer_id) {
                continue;
            }
            let connected_secs = now.saturating_sub(peer.connection_time.max(0) as u64);
            if connected_secs <= self.args.tx_spy_secs || sent_transactions(peer) {
                continue;
            }
            self.reported.insert(peer_id, ctx.now);
            out.push(Alert::TxSpy {
                peer_id,
                addr: peer.address.clone(),
                connected_secs,
            });
        }
    }

    fn on_peer_removed(&mut self, peer_id: u64) -> Option<Instant> {
        self.reported.remove(&peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{peer_info, peer_infos_event, EVENT_TIMESTAMP_SECS};
    use crate::heuristics::Peers;

    /// A peer connected `age` seconds before the test events, with the
    /// given messages received from it.
    fn peer(id: u32, relay: bool, age: u64, received: &[&str]) -> PeerInfo {
        let mut info = peer_info(id, "inbound", 0.0);
        info.relay_transactions = relay;
        info.connection_time = (EVENT_TIMESTAMP_SECS - age) as i64;
        for command in received {
            info.bytes_received_per_message
                .insert(command.to_string(), 100);
        }
        info
    }

    #[test]
    fn silent_relay_peers_are_reported_once() {
        let mut heuristic = TxSpy::new(TxSpyArgs { tx_spy_secs: 600 });
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        let poll = peer_infos_event(vec![
            // Silent for long enough: reported
            peer(1, true, 1200, &["ping", "pong"]),
            // Announced transactions: fine
            peer(2, true, 1200, &["ping", "inv"]),
            // Sent a transaction: fine
            peer(3, true, 1200, &["tx"]),
            // Asked for no relay: fine
            peer(4, false, 1200, &[]),
            // Too young to judge
            peer(5, true, 599, &[]),
        ]);
        heuristic.on_event(&poll, &ctx, &mut out);
        heuristic.on_event(&poll, &ctx, &mut out);
        assert_eq!(
            out,
            vec![Alert::TxSpy {
                peer_id: 1,
                addr: "10.0.0.1:8333".to_string(),
                connected_secs: 1200,
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
        assert_eq!(heuristic.on_peer_removed(2), None);
    }

    #[test]
    fn a_peer_that_left_and_came_back_is_judged_again() {
        let mut heuristic = TxSpy::new(TxSpyArgs { tx_spy_secs: 600 });
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        let silent = peer_infos_event(vec![peer(7, true, 1200, &[])]);
        heuristic.on_event(&silent, &ctx, &mut out);
        heuristic.on_event(&peer_infos_event(vec![]), &ctx, &mut out);
        heuristic.on_event(&silent, &ctx, &mut out);
        assert_eq!(out.len(), 2);
    }
}
