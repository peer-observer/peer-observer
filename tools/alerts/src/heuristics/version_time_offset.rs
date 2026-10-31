//! Flags peers whose clock is far off ours.
//!
//! Every `version` message carries the sender's current time. Bitcoin Core
//! compares it with its own clock and warns the operator when many peers are
//! more than ten minutes off, since a wrong clock breaks block validation.
//! From the other side, a peer with a clock far off either runs a broken
//! setup or sends made-up version messages. Either way it is worth a look.

use super::{inbound_message, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;

/// Bitcoin Core warns about its own clock at this offset.
pub const DEFAULT_VERSION_TIME_OFFSET_SECS: u64 = 10 * 60;

#[derive(clap::Args, Debug, Clone)]
pub struct VersionTimeOffsetArgs {
    /// Alert when a peer's version message time is off by more than this many seconds
    #[arg(long, default_value_t = DEFAULT_VERSION_TIME_OFFSET_SECS)]
    pub version_time_offset_secs: u64,
}

impl Default for VersionTimeOffsetArgs {
    fn default() -> Self {
        VersionTimeOffsetArgs {
            version_time_offset_secs: DEFAULT_VERSION_TIME_OFFSET_SECS,
        }
    }
}

pub struct VersionTimeOffset {
    args: VersionTimeOffsetArgs,
}

impl VersionTimeOffset {
    pub fn new(args: VersionTimeOffsetArgs) -> Self {
        VersionTimeOffset { args }
    }
}

impl Heuristic for VersionTimeOffset {
    fn on_event(&mut self, event: &Event, _ctx: &Context, out: &mut Vec<Alert>) {
        let Some(msg) = inbound_message(event) else {
            return;
        };
        let Some(Msg::Version(version)) = &msg.msg else {
            return;
        };
        // The event timestamp is the time the message was seen, in ms.
        let received_at = (event.timestamp / 1000) as i64;
        let offset_secs = version.timestamp - received_at;
        if offset_secs.unsigned_abs() <= self.args.version_time_offset_secs {
            return;
        }
        out.push(Alert::VersionTimeOffset {
            peer_id: msg.meta.peer_id,
            addr: msg.meta.addr.clone(),
            offset_secs,
            threshold_secs: self.args.version_time_offset_secs,
            user_agent: version.user_agent.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{version_at, EVENT_TIMESTAMP_SECS, PEER_ADDR};
    use crate::heuristics::Peers;
    use std::time::Instant;

    fn run(heuristic: &mut VersionTimeOffset, events: &[Event]) -> Vec<Alert> {
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
    fn clocks_off_in_either_direction_alert() {
        let mut heuristic = VersionTimeOffset::new(VersionTimeOffsetArgs {
            version_time_offset_secs: 600,
        });
        let now = EVENT_TIMESTAMP_SECS as i64;
        let events = [
            version_at(1, true, now),
            version_at(2, true, now - 600),
            version_at(3, true, now + 600),
            version_at(4, true, now - 601),
            version_at(5, true, now + 3600),
        ];
        let alerts = run(&mut heuristic, &events);
        assert_eq!(
            alerts,
            vec![
                Alert::VersionTimeOffset {
                    peer_id: 4,
                    addr: PEER_ADDR.to_string(),
                    offset_secs: -601,
                    threshold_secs: 600,
                    user_agent: "/test/".to_string(),
                },
                Alert::VersionTimeOffset {
                    peer_id: 5,
                    addr: PEER_ADDR.to_string(),
                    offset_secs: 3600,
                    threshold_secs: 600,
                    user_agent: "/test/".to_string(),
                },
            ]
        );
    }
}
