//! Reports peers that Bitcoin Core itself flags as misbehaving, for example
//! for sending too many headers or an invalid block. Core logs the reason and
//! usually disconnects the peer right away. The ebpf-extractor passes the
//! reason on as a connection event, which this heuristic turns into an alert.

use super::{connection_event, Context, Heuristic};
use crate::alerter::Alert;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;

pub struct MisbehavingPeer;

impl Heuristic for MisbehavingPeer {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(ConnectionEvent::Misbehaving(misbehaving)) = connection_event(event) else {
            return;
        };
        // The event only carries the peer id. We know the address if we saw
        // the connection open or a message from the peer before.
        let addr = ctx
            .peers
            .get(&misbehaving.id)
            .map(|peer| peer.addr.clone())
            .unwrap_or_else(|| "unknown".to_string());
        out.push(Alert::MisbehavingPeer {
            peer_id: misbehaving.id,
            addr,
            reason: misbehaving.message.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{connection, PEER_ADDR};
    use crate::heuristics::{Peer, Peers};
    use shared::protobuf::ebpf_extractor::connection::MisbehavingConnection;
    use std::time::Instant;

    fn misbehaving(peer_id: u64, message: &str) -> Event {
        connection(ConnectionEvent::Misbehaving(MisbehavingConnection {
            id: peer_id,
            message: message.to_string(),
        }))
    }

    #[test]
    fn reports_every_misbehaving_event() {
        let now = Instant::now();
        let mut peers = Peers::new();
        peers.insert(
            3,
            Peer {
                addr: PEER_ADDR.to_string(),
                last_seen: now,
                user_agent: None,
                network: None,
            },
        );
        let ctx = Context { now, peers: &peers };
        let mut heuristic = MisbehavingPeer;
        let mut out = Vec::new();
        heuristic.on_event(
            &misbehaving(3, "headers message size = 2001"),
            &ctx,
            &mut out,
        );
        heuristic.on_event(&misbehaving(3, "invalid header received"), &ctx, &mut out);
        assert_eq!(
            out,
            vec![
                Alert::MisbehavingPeer {
                    peer_id: 3,
                    addr: PEER_ADDR.to_string(),
                    reason: "headers message size = 2001".to_string(),
                },
                Alert::MisbehavingPeer {
                    peer_id: 3,
                    addr: PEER_ADDR.to_string(),
                    reason: "invalid header received".to_string(),
                },
            ]
        );
        assert_eq!(heuristic.on_peer_removed(3), None);
    }

    #[test]
    fn unknown_peers_get_an_unknown_address() {
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        MisbehavingPeer.on_event(&misbehaving(9, "bad"), &ctx, &mut out);
        assert_eq!(
            out,
            vec![Alert::MisbehavingPeer {
                peer_id: 9,
                addr: "unknown".to_string(),
                reason: "bad".to_string(),
            }]
        );
    }
}
