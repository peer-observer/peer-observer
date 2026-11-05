//! Alerts when many peers have not answered our ping for a long time.
//!
//! Bitcoin Core pings every peer regularly and `getpeerinfo` reports how long
//! the current ping has been waiting for its pong. One slow peer is normal.
//! Many peers waiting at once means the problem is on our side: the node is
//! overloaded, its network is stalling, or the message handling thread is
//! stuck. This was the first visible sign in peer-observer issue 198.

use super::{peer_infos, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::event::Event;

pub const DEFAULT_PING_WAIT_SECS: u64 = 5;
pub const DEFAULT_PING_WAIT_PEERS: usize = 10;

#[derive(clap::Args, Debug, Clone)]
pub struct HighPingWaitArgs {
    /// A ping counts as waiting too long after this many seconds without a pong
    #[arg(long, default_value_t = DEFAULT_PING_WAIT_SECS)]
    pub ping_wait_secs: u64,

    /// Number of peers waiting too long for a pong before alerting
    #[arg(long, default_value_t = DEFAULT_PING_WAIT_PEERS)]
    pub ping_wait_peers: usize,
}

impl Default for HighPingWaitArgs {
    fn default() -> Self {
        HighPingWaitArgs {
            ping_wait_secs: DEFAULT_PING_WAIT_SECS,
            ping_wait_peers: DEFAULT_PING_WAIT_PEERS,
        }
    }
}

pub struct HighPingWait {
    args: HighPingWaitArgs,
    /// False while an episode is being reported.
    armed: bool,
}

impl HighPingWait {
    pub fn new(args: HighPingWaitArgs) -> Self {
        HighPingWait { args, armed: true }
    }
}

impl Heuristic for HighPingWait {
    fn on_event(&mut self, event: &Event, _ctx: &Context, out: &mut Vec<Alert>) {
        let Some(infos) = peer_infos(event) else {
            return;
        };
        let wait_ms = (self.args.ping_wait_secs * 1000) as f64;
        let waiting = infos
            .infos
            .iter()
            .filter(|peer| peer.ping_wait > wait_ms)
            .count();
        if waiting <= self.args.ping_wait_peers {
            self.armed = true;
            return;
        }
        if !self.armed {
            return;
        }
        self.armed = false;
        out.push(Alert::HighPingWait {
            peers: waiting,
            total_peers: infos.infos.len(),
            wait_secs: self.args.ping_wait_secs,
            threshold_peers: self.args.ping_wait_peers,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{peer_info, peer_infos_event};
    use crate::heuristics::Peers;
    use std::time::Instant;

    fn run(heuristic: &mut HighPingWait, events: &[Event]) -> Vec<Alert> {
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

    fn poll(waiting: usize, fine: usize) -> Event {
        let mut infos = Vec::new();
        for id in 0..waiting {
            infos.push(peer_info(id as u32, "inbound", 6000.0));
        }
        for id in waiting..waiting + fine {
            infos.push(peer_info(id as u32, "inbound", 0.0));
        }
        peer_infos_event(infos)
    }

    #[test]
    fn many_waiting_peers_alert_once_until_recovered() {
        let mut heuristic = HighPingWait::new(HighPingWaitArgs {
            ping_wait_secs: 5,
            ping_wait_peers: 2,
        });
        let events = [
            poll(2, 10),
            poll(3, 10),
            poll(5, 5),
            poll(1, 10),
            poll(3, 0),
        ];
        assert_eq!(
            run(&mut heuristic, &events),
            vec![
                Alert::HighPingWait {
                    peers: 3,
                    total_peers: 13,
                    wait_secs: 5,
                    threshold_peers: 2,
                },
                Alert::HighPingWait {
                    peers: 3,
                    total_peers: 3,
                    wait_secs: 5,
                    threshold_peers: 2,
                },
            ]
        );
    }
}
