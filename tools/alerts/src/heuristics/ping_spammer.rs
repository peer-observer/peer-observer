//! Flags peers that send us too many `ping` messages in a short time.

use super::{inbound_message, Context, Heuristic, PerPeerWindowCounter};
use crate::alerter::{Alert, SpammerKind};
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::time::{Duration, Instant};

pub const DEFAULT_PING_THRESHOLD: usize = 3;
pub const DEFAULT_PING_WINDOW_SECS: u64 = 120;

#[derive(clap::Args, Debug, Clone)]
pub struct PingSpammerArgs {
    /// Number of pings in the window before alerting
    #[arg(long, default_value_t = DEFAULT_PING_THRESHOLD)]
    pub ping_threshold: usize,

    /// Sliding window size for ping detection (seconds)
    #[arg(long, default_value_t = DEFAULT_PING_WINDOW_SECS)]
    pub ping_window_secs: u64,
}

impl Default for PingSpammerArgs {
    fn default() -> Self {
        PingSpammerArgs {
            ping_threshold: DEFAULT_PING_THRESHOLD,
            ping_window_secs: DEFAULT_PING_WINDOW_SECS,
        }
    }
}

pub struct PingSpammer {
    args: PingSpammerArgs,
    counter: PerPeerWindowCounter,
}

impl PingSpammer {
    pub fn new(args: PingSpammerArgs) -> Self {
        let counter = PerPeerWindowCounter::new(
            Duration::from_secs(args.ping_window_secs),
            args.ping_threshold,
        );
        PingSpammer { args, counter }
    }
}

impl Heuristic for PingSpammer {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        if !matches!(msg.msg, Some(Msg::Ping(_))) {
            return;
        }
        if let Some(count) = self.counter.hit(msg.meta.peer_id, ctx.now) {
            out.push(Alert::Spammer {
                kind: SpammerKind::Ping,
                peer_id: msg.meta.peer_id,
                addr: msg.meta.addr.clone(),
                count,
                window_secs: self.args.ping_window_secs,
                threshold: self.args.ping_threshold,
            });
        }
    }

    fn on_peer_removed(&mut self, peer_id: u64) -> Option<Instant> {
        self.counter.remove(peer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{message, PEER_ADDR};
    use crate::heuristics::Peers;
    use shared::protobuf::ebpf_extractor::message::Ping;

    fn ping(peer_id: u64, inbound: bool) -> Event {
        message(peer_id, inbound, "ping", Msg::Ping(Ping { value: 42 }))
    }

    fn run(heuristic: &mut PingSpammer, events: &[Event]) -> Vec<Alert> {
        let peers = Peers::new();
        let now = Instant::now();
        let mut out = Vec::new();
        for (i, event) in events.iter().enumerate() {
            let ctx = Context {
                now: now + Duration::from_millis(i as u64),
                peers: &peers,
            };
            heuristic.on_event(event, &ctx, &mut out);
        }
        out
    }

    #[test]
    fn alerts_once_above_the_threshold() {
        let mut heuristic = PingSpammer::new(PingSpammerArgs {
            ping_threshold: 3,
            ping_window_secs: 60,
        });
        let alerts = run(&mut heuristic, &vec![ping(1, true); 10]);
        assert_eq!(
            alerts,
            vec![Alert::Spammer {
                kind: SpammerKind::Ping,
                peer_id: 1,
                addr: PEER_ADDR.to_string(),
                count: 4,
                window_secs: 60,
                threshold: 3,
            }]
        );
        assert!(heuristic.on_peer_removed(1).is_some());
    }

    #[test]
    fn ignores_our_own_pings_and_other_messages() {
        let mut heuristic = PingSpammer::new(PingSpammerArgs {
            ping_threshold: 0,
            ping_window_secs: 60,
        });
        let mut events = vec![ping(1, false); 3];
        events.push(message(
            1,
            true,
            "pong",
            Msg::Pong(shared::protobuf::ebpf_extractor::message::Pong { value: 42 }),
        ));
        assert!(run(&mut heuristic, &events).is_empty());
        assert_eq!(heuristic.on_peer_removed(1), None);
    }
}
