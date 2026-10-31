//! Alerts on addresses that connect to us over and over.
//!
//! A node connects once and stays. An address that opens a new connection
//! to us every few minutes is cycling connections: a crawler coming back for
//! more addresses, a monitor trying to be the first to hear our
//! transactions, or software stuck in a reconnect loop. Each connection gets
//! a fresh peer id, so per-connection alerts repeat for it. This heuristic
//! counts connection opens per host and reports a host once per episode.
//!
//! On the demo node about seven addresses per hour open more than ten
//! connections in that hour, and twenty open more than five.

use super::{connection_event, host_of, is_loopback, Context, Heuristic, ThresholdWindow};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::ebpf_extractor::connection::connection_event::Event as ConnectionEvent;
use shared::protobuf::event::Event;
use std::collections::HashMap;
use std::time::Duration;

pub const DEFAULT_CYCLING_THRESHOLD: usize = 10;
pub const DEFAULT_CYCLING_WINDOW_SECS: u64 = 3600;
pub const DEFAULT_CYCLING_REPEAT_SECS: u64 = 86400;

#[derive(clap::Args, Debug, Clone)]
pub struct ConnectionCyclingArgs {
    /// Number of inbound connections from one address in the window before alerting
    #[arg(long, default_value_t = DEFAULT_CYCLING_THRESHOLD)]
    pub cycling_threshold: usize,

    /// Sliding window size for connection cycling detection (seconds)
    #[arg(long, default_value_t = DEFAULT_CYCLING_WINDOW_SECS)]
    pub cycling_window_secs: u64,

    /// Report an address that keeps cycling at most once per this many seconds
    #[arg(long, default_value_t = DEFAULT_CYCLING_REPEAT_SECS)]
    pub cycling_repeat_secs: u64,
}

impl Default for ConnectionCyclingArgs {
    fn default() -> Self {
        ConnectionCyclingArgs {
            cycling_threshold: DEFAULT_CYCLING_THRESHOLD,
            cycling_window_secs: DEFAULT_CYCLING_WINDOW_SECS,
            cycling_repeat_secs: DEFAULT_CYCLING_REPEAT_SECS,
        }
    }
}

pub struct ConnectionCycling {
    args: ConnectionCyclingArgs,
    hosts: HashMap<String, ThresholdWindow>,
}

impl ConnectionCycling {
    pub fn new(args: ConnectionCyclingArgs) -> Self {
        ConnectionCycling {
            args,
            hosts: HashMap::new(),
        }
    }
}

impl Heuristic for ConnectionCycling {
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>) {
        let Some(ConnectionEvent::Inbound(inbound)) = connection_event(event) else {
            return;
        };
        // Inbound Tor connections all arrive from localhost and cannot be
        // told apart by address, and local tools are the operator's own.
        if is_loopback(&inbound.conn.addr) {
            return;
        }
        let host = host_of(&inbound.conn.addr).to_string();
        let window = Duration::from_secs(self.args.cycling_window_secs);
        let threshold = self.args.cycling_threshold;
        let opens = self.hosts.entry(host.clone()).or_insert_with(|| {
            ThresholdWindow::with_repeat(
                window,
                threshold,
                Duration::from_secs(self.args.cycling_repeat_secs),
            )
        });
        if let Some(count) = opens.record(ctx.now) {
            out.push(Alert::ConnectionCycling {
                host,
                count,
                window_secs: self.args.cycling_window_secs,
                threshold,
            });
        }
    }

    fn on_tick(&mut self, ctx: &Context, _out: &mut Vec<Alert>) {
        self.hosts.retain(|_, opens| {
            opens.tick(ctx.now);
            !opens.is_idle(ctx.now)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{connection, inbound_connection};
    use crate::heuristics::Peers;
    use shared::protobuf::bitcoin_primitives::ConnType;
    use shared::protobuf::ebpf_extractor::connection::{Connection, InboundConnection};
    use std::time::Instant;

    fn inbound_from(peer_id: u64, addr: &str) -> Event {
        connection(ConnectionEvent::Inbound(InboundConnection {
            conn: Connection {
                peer_id,
                addr: addr.to_string(),
                conn_type: ConnType::Inbound as i32,
                network: 1,
            },
            existing_connections: 1,
        }))
    }

    #[test]
    fn repeated_connections_from_one_host_alert_once() {
        let mut heuristic = ConnectionCycling::new(ConnectionCyclingArgs {
            cycling_threshold: 2,
            cycling_window_secs: 60,
            cycling_repeat_secs: 60,
        });
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        // Different ports, same host
        for (peer_id, addr) in [
            (1, "1.2.3.4:1000"),
            (2, "5.6.7.8:1000"),
            (3, "1.2.3.4:1001"),
            (4, "1.2.3.4:1002"),
            (5, "1.2.3.4:1003"),
        ] {
            heuristic.on_event(&inbound_from(peer_id, addr), &ctx, &mut out);
        }
        heuristic.on_event(&inbound_connection(6), &ctx, &mut out);
        // Localhost is Tor inbound or our own tools, and is not counted
        for peer_id in 7..=12 {
            heuristic.on_event(&inbound_from(peer_id, "127.0.0.1:9000"), &ctx, &mut out);
        }
        assert_eq!(
            out,
            vec![Alert::ConnectionCycling {
                host: "1.2.3.4".to_string(),
                count: 3,
                window_secs: 60,
                threshold: 2,
            }]
        );
        assert_eq!(heuristic.hosts.len(), 2);
    }
}
