//! Flags peers that keep sending messages we do not know.
//!
//! The extractor marks every P2P message whose command rust-bitcoin does not
//! implement as unknown. Bitcoin Core ignores such messages. One or two can be
//! a newer client with a feature we do not parse yet. A peer sending many of
//! them is fuzzing, probing how we react, or badly broken.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Instant;

pub const DEFAULT_UNKNOWN_MESSAGE_THRESHOLD: usize = 3;

#[derive(clap::Args, Debug, Clone)]
pub struct UnknownMessagesArgs {
    /// Number of unknown messages from one peer before alerting
    #[arg(long, default_value_t = DEFAULT_UNKNOWN_MESSAGE_THRESHOLD)]
    pub unknown_message_threshold: usize,
}

impl Default for UnknownMessagesArgs {
    fn default() -> Self {
        UnknownMessagesArgs {
            unknown_message_threshold: DEFAULT_UNKNOWN_MESSAGE_THRESHOLD,
        }
    }
}

#[derive(Default)]
struct PeerState {
    count: usize,
    alerted_at: Option<Instant>,
}

pub struct UnknownMessages {
    args: UnknownMessagesArgs,
    peers: HashMap<u64, PeerState>,
}

impl UnknownMessages {
    pub fn new(args: UnknownMessagesArgs) -> Self {
        UnknownMessages {
            args,
            peers: HashMap::new(),
        }
    }
}

impl Heuristic for UnknownMessages {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        let Some(Msg::Unknown(unknown)) = &msg.msg else {
            return;
        };
        let peer = self.peers.entry(msg.meta.peer_id).or_default();
        if peer.alerted_at.is_some() {
            return;
        }
        peer.count += 1;
        if peer.count <= self.args.unknown_message_threshold {
            return;
        }
        peer.alerted_at = Some(ctx.now);
        out.push(Alert::UnknownMessages {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            count: peer.count,
            threshold: self.args.unknown_message_threshold,
            last_command: unknown.command.clone(),
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
    use shared::protobuf::ebpf_extractor::message::{Ping, Unknown};

    fn unknown(peer_id: u64, command: &str) -> Event {
        message(
            peer_id,
            true,
            command,
            Msg::Unknown(Unknown {
                command: command.to_string(),
                payload: vec![],
            }),
        )
    }

    fn run(heuristic: &mut UnknownMessages, events: &[Event]) -> Vec<Alert> {
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
    fn unknown_messages_above_the_threshold_alert_once() {
        let mut heuristic = UnknownMessages::new(UnknownMessagesArgs {
            unknown_message_threshold: 2,
        });
        let events = [
            unknown(1, "foo"),
            message(1, true, "ping", Msg::Ping(Ping { value: 1 })),
            unknown(1, "bar"),
            unknown(1, "baz"),
            unknown(1, "qux"),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![Alert::UnknownMessages {
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                count: 3,
                threshold: 2,
                last_command: "baz".to_string(),
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
    }

    #[test]
    fn our_own_unknown_messages_do_not_count() {
        let mut heuristic = UnknownMessages::new(UnknownMessagesArgs {
            unknown_message_threshold: 0,
        });
        let ours = message(
            1,
            false,
            "foo",
            Msg::Unknown(Unknown {
                command: "foo".to_string(),
                payload: vec![],
            }),
        );
        assert!(run(&mut heuristic, &[ours]).is_empty());
    }
}
