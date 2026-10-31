//! Flags peers that send handshake messages after the handshake is over.
//!
//! The P2P handshake is `version`, optional feature negotiation like
//! `wtxidrelay` and `sendaddrv2`, and then `verack`. After its `verack` a peer
//! has no reason to send any of these again. Bitcoin Core ignores late
//! `version`, `verack`, `wtxidrelay` and `sendaddrv2` messages and disconnects
//! peers that send `sendtxrcncl` after `verack`. Peers doing this are either
//! buggy or probing how we react.
//!
//! A peer is only checked once we have seen its `verack`. Peers connected
//! before the tool started are not checked.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Instant;

/// Messages that only belong into the handshake.
const HANDSHAKE_COMMANDS: [&str; 5] = [
    "version",
    "verack",
    "wtxidrelay",
    "sendaddrv2",
    "sendtxrcncl",
];

#[derive(Default)]
struct PeerState {
    verack_seen: bool,
    alerted_at: Option<Instant>,
}

#[derive(Default)]
pub struct HandshakeAfterVerack {
    peers: HashMap<u64, PeerState>,
}

impl Heuristic for HandshakeAfterVerack {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        let command = msg.meta.command.as_str();
        if !HANDSHAKE_COMMANDS.contains(&command) {
            return;
        }
        let peer = self.peers.entry(msg.meta.peer_id).or_default();
        if !peer.verack_seen {
            if command == "verack" {
                peer.verack_seen = true;
            }
            return;
        }
        if peer.alerted_at.is_some() {
            return;
        }
        peer.alerted_at = Some(ctx.now);
        out.push(Alert::HandshakeAfterVerack {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            command: command.to_string(),
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
    use shared::protobuf::ebpf_extractor::message::message_event::Msg;
    use shared::protobuf::ebpf_extractor::message::Ping;

    fn verack(peer_id: u64, inbound: bool) -> Event {
        message(peer_id, inbound, "verack", Msg::Verack(true))
    }

    fn wtxidrelay(peer_id: u64) -> Event {
        message(peer_id, true, "wtxidrelay", Msg::Wtxidrelay(true))
    }

    fn run(heuristic: &mut HandshakeAfterVerack, events: &[Event]) -> Vec<Alert> {
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
    fn handshake_message_after_verack_alerts_once() {
        let mut heuristic = HandshakeAfterVerack::default();
        let events = [
            wtxidrelay(1),
            verack(1, true),
            message(1, true, "ping", Msg::Ping(Ping { value: 1 })),
            wtxidrelay(1),
            message(1, true, "sendaddrv2", Msg::Sendaddrv2(true)),
            verack(1, true),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::HandshakeAfterVerack {
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                command: "wtxidrelay".to_string(),
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
    }

    #[test]
    fn no_alert_without_an_inbound_verack() {
        let mut heuristic = HandshakeAfterVerack::default();
        // Our own verack does not count, and handshake messages before the
        // peer's verack are normal
        let events = [verack(1, false), wtxidrelay(1), wtxidrelay(1)];
        assert!(run(&mut heuristic, &events).is_empty());
        assert_eq!(heuristic.on_peer_removed(1), None);
    }

    #[test]
    fn peers_are_tracked_separately() {
        let mut heuristic = HandshakeAfterVerack::default();
        let events = [
            verack(1, true),
            wtxidrelay(2),
            verack(2, true),
            wtxidrelay(1),
        ];
        let alerts = run(&mut heuristic, &events);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(
            alerts[0],
            Alert::HandshakeAfterVerack { peer_id: 1, .. }
        ));
    }
}
