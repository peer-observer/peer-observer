//! Flags peers whose `ping` nonces are suspiciously small.
//!
//! Bitcoin Core draws eight random bytes for every ping nonce, so a nonce
//! below 2^32 happens about once in four billion pings. A peer that sends
//! several of them uses a counter or a 32-bit random number and is not a
//! Bitcoin Core node, whatever its user agent says.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Instant;

pub const DEFAULT_SMALL_PING_NONCE_THRESHOLD: usize = 3;

/// Nonces below this value fit into 32 bits.
const SMALL_NONCE_LIMIT: u64 = 1 << 32;

#[derive(clap::Args, Debug, Clone)]
pub struct SmallPingNonceArgs {
    /// Number of pings with a nonce below 2^32 from one peer before alerting
    #[arg(long, default_value_t = DEFAULT_SMALL_PING_NONCE_THRESHOLD)]
    pub small_ping_nonce_threshold: usize,
}

impl Default for SmallPingNonceArgs {
    fn default() -> Self {
        SmallPingNonceArgs {
            small_ping_nonce_threshold: DEFAULT_SMALL_PING_NONCE_THRESHOLD,
        }
    }
}

#[derive(Default)]
struct PeerState {
    small_nonces: usize,
    alerted_at: Option<Instant>,
}

pub struct SmallPingNonce {
    args: SmallPingNonceArgs,
    peers: HashMap<u64, PeerState>,
}

impl SmallPingNonce {
    pub fn new(args: SmallPingNonceArgs) -> Self {
        SmallPingNonce {
            args,
            peers: HashMap::new(),
        }
    }
}

impl Heuristic for SmallPingNonce {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        let Some(Msg::Ping(ping)) = &msg.msg else {
            return;
        };
        if ping.value >= SMALL_NONCE_LIMIT {
            return;
        }
        let peer = self.peers.entry(msg.meta.peer_id).or_default();
        if peer.alerted_at.is_some() {
            return;
        }
        peer.small_nonces += 1;
        if peer.small_nonces <= self.args.small_ping_nonce_threshold {
            return;
        }
        peer.alerted_at = Some(ctx.now);
        out.push(Alert::SmallPingNonce {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            count: peer.small_nonces,
            threshold: self.args.small_ping_nonce_threshold,
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
    use shared::protobuf::ebpf_extractor::message::Ping;

    fn ping(peer_id: u64, value: u64) -> Event {
        message(peer_id, true, "ping", Msg::Ping(Ping { value }))
    }

    fn run(heuristic: &mut SmallPingNonce, events: &[Event]) -> Vec<Alert> {
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
    fn small_nonces_above_the_threshold_alert_once() {
        let mut heuristic = SmallPingNonce::new(SmallPingNonceArgs {
            small_ping_nonce_threshold: 2,
        });
        let events = [
            ping(1, 0),
            ping(1, 7),
            ping(1, u32::MAX as u64),
            ping(1, 8),
            ping(1, 9),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::SmallPingNonce {
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                count: 3,
                threshold: 2,
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
    }

    #[test]
    fn full_size_nonces_do_not_count() {
        let mut heuristic = SmallPingNonce::new(SmallPingNonceArgs {
            small_ping_nonce_threshold: 0,
        });
        let events = [
            ping(1, 1 << 32),
            ping(1, u64::MAX),
            message(1, false, "ping", Msg::Ping(Ping { value: 1 })),
        ];
        assert!(run(&mut heuristic, &events).is_empty());
        assert_eq!(heuristic.on_peer_removed(1), None);
    }
}
