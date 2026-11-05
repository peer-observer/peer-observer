//! Flags peers that announce or send transactions after telling us they do
//! not want transaction relay.
//!
//! A peer sets `relay=false` in its `version` message to ask us not to announce
//! transactions to it, as block-relay-only connections and nodes running with
//! `-blocksonly` do. Such a node has no unconfirmed transactions to share
//! either. A peer that sets the flag and still sends us `inv` messages with
//! transactions or `tx` messages is behaving inconsistently. BIP 37 allows a
//! peer to turn relay back on by loading a bloom filter, so `filterload` and
//! `filterclear` from the peer end the check.
//!
//! Only peers whose `version` message the tool has seen are checked.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::protobuf::bitcoin_primitives::inventory_item::Item;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Default)]
struct PeerState {
    relay_disabled: bool,
    alerted_at: Option<Instant>,
}

#[derive(Default)]
pub struct TxRelayMismatch {
    peers: HashMap<u64, PeerState>,
}

impl Heuristic for TxRelayMismatch {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        let relays_transactions = match &msg.msg {
            Some(Msg::Version(version)) => {
                self.peers
                    .entry(msg.meta.peer_id)
                    .or_default()
                    .relay_disabled = !version.relay;
                return;
            }
            Some(Msg::Filterload(_)) | Some(Msg::Filterclear(_)) => {
                if let Some(peer) = self.peers.get_mut(&msg.meta.peer_id) {
                    peer.relay_disabled = false;
                }
                return;
            }
            Some(Msg::Tx(_)) => true,
            Some(Msg::Inv(inv)) => inv.items.iter().any(|item| {
                matches!(
                    item.item,
                    Some(Item::Transaction(_))
                        | Some(Item::Wtx(_))
                        | Some(Item::WitnessTransaction(_))
                )
            }),
            _ => false,
        };
        if !relays_transactions {
            return;
        }
        let Some(peer) = self.peers.get_mut(&msg.meta.peer_id) else {
            return;
        };
        if !peer.relay_disabled || peer.alerted_at.is_some() {
            return;
        }
        peer.alerted_at = Some(ctx.now);
        out.push(Alert::TxRelayMismatch {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            command: msg.meta.command.clone(),
        });
    }

    fn on_peer_removed(&mut self, peer_id: u64) -> Option<Instant> {
        self.peers.remove(&peer_id).and_then(|p| p.alerted_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{inv, message, version, PEER_ADDR};
    use crate::heuristics::Peers;
    use shared::protobuf::bitcoin_primitives::InventoryItem;

    fn tx_inv(peer_id: u64) -> Event {
        inv(peer_id, vec![Item::Wtx(vec![1; 32])])
    }

    fn block_inv(peer_id: u64) -> Event {
        inv(peer_id, vec![Item::Block(vec![2; 32])])
    }

    fn run(heuristic: &mut TxRelayMismatch, events: &[Event]) -> Vec<Alert> {
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
    fn transactions_after_relay_false_alert_once() {
        let mut heuristic = TxRelayMismatch::default();
        let events = [
            version(1, false),
            block_inv(1),
            inv(1, vec![]),
            tx_inv(1),
            tx_inv(1),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::TxRelayMismatch {
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                command: "inv".to_string(),
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
    }

    #[test]
    fn relay_true_or_unknown_version_is_fine() {
        let mut heuristic = TxRelayMismatch::default();
        // Peer 1 allows relay, peer 2 never sent a version we saw
        let events = [version(1, true), tx_inv(1), tx_inv(2)];
        assert!(run(&mut heuristic, &events).is_empty());
    }

    #[test]
    fn loading_a_filter_turns_relay_back_on() {
        let mut heuristic = TxRelayMismatch::default();
        let filterclear = message(1, true, "filterclear", Msg::Filterclear(true));
        let events = [version(1, false), filterclear, tx_inv(1)];
        assert!(run(&mut heuristic, &events).is_empty());
    }

    #[test]
    fn our_own_messages_do_not_count() {
        let mut heuristic = TxRelayMismatch::default();
        let our_inv = message(
            1,
            false,
            "inv",
            Msg::Inv(shared::protobuf::ebpf_extractor::message::Inv {
                items: vec![InventoryItem {
                    item: Some(Item::Wtx(vec![1; 32])),
                }],
            }),
        );
        let events = [version(1, false), our_inv];
        assert!(run(&mut heuristic, &events).is_empty());
    }
}
