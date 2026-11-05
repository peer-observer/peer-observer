//! Flags peers that send us too many `addr` and `addrv2` messages in a short
//! time. Both message types count towards the same window.

use super::{inbound_message, Context, Heuristic, PerPeerWindowCounter};
use crate::alerter::{Alert, SpammerKind};
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use std::time::{Duration, Instant};

pub const DEFAULT_ADDR_THRESHOLD: usize = 6;
pub const DEFAULT_ADDR_WINDOW_SECS: u64 = 60;

#[derive(clap::Args, Debug, Clone)]
pub struct AddrSpammerArgs {
    /// Number of addr/addrv2 messages in the window before alerting
    #[arg(long, default_value_t = DEFAULT_ADDR_THRESHOLD)]
    pub addr_threshold: usize,

    /// Sliding window size for addr detection (seconds)
    #[arg(long, default_value_t = DEFAULT_ADDR_WINDOW_SECS)]
    pub addr_window_secs: u64,
}

impl Default for AddrSpammerArgs {
    fn default() -> Self {
        AddrSpammerArgs {
            addr_threshold: DEFAULT_ADDR_THRESHOLD,
            addr_window_secs: DEFAULT_ADDR_WINDOW_SECS,
        }
    }
}

pub struct AddrSpammer {
    args: AddrSpammerArgs,
    counter: PerPeerWindowCounter,
}

impl AddrSpammer {
    pub fn new(args: AddrSpammerArgs) -> Self {
        let counter = PerPeerWindowCounter::new(
            Duration::from_secs(args.addr_window_secs),
            args.addr_threshold,
        );
        AddrSpammer { args, counter }
    }
}

impl Heuristic for AddrSpammer {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        if !matches!(msg.msg, Some(Msg::Addr(_)) | Some(Msg::Addrv2(_))) {
            return;
        }
        if let Some(count) = self.counter.hit(msg.meta.peer_id, ctx.now) {
            out.push(Alert::Spammer {
                kind: SpammerKind::Addr,
                peer_id: msg.meta.peer_id,
                addr: msg.meta.addr.clone(),
                count,
                window_secs: self.args.addr_window_secs,
                threshold: self.args.addr_threshold,
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
    use shared::protobuf::ebpf_extractor::message::{Addr, AddrV2};

    fn addr(peer_id: u64) -> Event {
        message(peer_id, true, "addr", Msg::Addr(Addr { addresses: vec![] }))
    }

    fn addrv2(peer_id: u64) -> Event {
        message(
            peer_id,
            true,
            "addrv2",
            Msg::Addrv2(AddrV2 { addresses: vec![] }),
        )
    }

    fn run(heuristic: &mut AddrSpammer, events: &[Event]) -> Vec<Alert> {
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
    fn addr_and_addrv2_share_one_window() {
        let mut heuristic = AddrSpammer::new(AddrSpammerArgs {
            addr_threshold: 2,
            addr_window_secs: 60,
        });
        let alerts = run(&mut heuristic, &[addr(7), addrv2(7), addr(7), addrv2(7)]);
        assert_eq!(
            alerts,
            vec![Alert::Spammer {
                kind: SpammerKind::Addr,
                peer_id: 7,
                addr: PEER_ADDR.to_string(),
                count: 3,
                window_secs: 60,
                threshold: 2,
            }]
        );
    }

    #[test]
    fn pings_do_not_count_as_addr_messages() {
        let mut heuristic = AddrSpammer::new(AddrSpammerArgs {
            addr_threshold: 0,
            addr_window_secs: 60,
        });
        let ping = message(
            1,
            true,
            "ping",
            Msg::Ping(shared::protobuf::ebpf_extractor::message::Ping { value: 1 }),
        );
        assert!(run(&mut heuristic, &[ping]).is_empty());
    }
}
