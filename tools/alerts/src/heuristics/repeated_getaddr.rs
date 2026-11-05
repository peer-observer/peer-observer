//! Flags peers that ask for addresses more than once.
//!
//! A node sends one `getaddr` after the handshake to learn about other
//! nodes. Bitcoin Core answers a `getaddr` only once per connection and
//! ignores the rest, so a second one gains an honest node nothing. Peers that
//! keep asking are address crawlers that have not read the rules or hope we
//! are a different implementation.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Instant;

pub const DEFAULT_GETADDR_THRESHOLD: usize = 1;

#[derive(clap::Args, Debug, Clone)]
pub struct RepeatedGetaddrArgs {
    /// Number of getaddr messages from one peer before alerting
    #[arg(long, default_value_t = DEFAULT_GETADDR_THRESHOLD)]
    pub getaddr_threshold: usize,
}

impl Default for RepeatedGetaddrArgs {
    fn default() -> Self {
        RepeatedGetaddrArgs {
            getaddr_threshold: DEFAULT_GETADDR_THRESHOLD,
        }
    }
}

#[derive(Default)]
struct PeerState {
    count: usize,
    alerted_at: Option<Instant>,
}

pub struct RepeatedGetaddr {
    args: RepeatedGetaddrArgs,
    peers: HashMap<u64, PeerState>,
}

impl RepeatedGetaddr {
    pub fn new(args: RepeatedGetaddrArgs) -> Self {
        RepeatedGetaddr {
            args,
            peers: HashMap::new(),
        }
    }
}

impl Heuristic for RepeatedGetaddr {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        if !matches!(msg.msg, Some(Msg::Getaddr(_))) {
            return;
        }
        let peer = self.peers.entry(msg.meta.peer_id).or_default();
        if peer.alerted_at.is_some() {
            return;
        }
        peer.count += 1;
        if peer.count <= self.args.getaddr_threshold {
            return;
        }
        peer.alerted_at = Some(ctx.now);
        out.push(Alert::RepeatedGetaddr {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            count: peer.count,
            threshold: self.args.getaddr_threshold,
        });
    }

    fn on_peer_removed(&mut self, peer_id: u64) -> Option<Instant> {
        self.peers.remove(&peer_id).and_then(|p| p.alerted_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{message, PEER_ADDR};
    use crate::heuristics::Peers;

    fn getaddr(peer_id: u64, inbound: bool) -> Event {
        message(peer_id, inbound, "getaddr", Msg::Getaddr(true))
    }

    fn run(heuristic: &mut RepeatedGetaddr, events: &[Event]) -> Vec<Alert> {
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
    fn a_second_getaddr_alerts_once() {
        let mut heuristic = RepeatedGetaddr::new(RepeatedGetaddrArgs::default());
        let events = [
            getaddr(1, true),
            getaddr(2, true),
            getaddr(1, false),
            getaddr(1, true),
            getaddr(1, true),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::RepeatedGetaddr {
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                count: 2,
                threshold: 1,
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
        assert_eq!(heuristic.on_peer_removed(2), None);
    }
}
