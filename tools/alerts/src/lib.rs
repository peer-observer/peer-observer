#![cfg_attr(feature = "strict", deny(warnings))]

use shared::anyhow::{Context as _, Result};
use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::nats_subjects::Subject;
use shared::nats_util;
use shared::nats_util::NatsArgs;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::connection::connection_event;
use shared::protobuf::event::Event;
use shared::tokio::sync::watch;
use std::time::{Duration, Instant};

pub mod alerter;
pub mod heuristics;

pub use crate::alerter::{Alert, Alerter, LoggingAlerter, SpammerKind};
use crate::heuristics::addr_spammer::{AddrSpammer, AddrSpammerArgs};
use crate::heuristics::handshake_after_verack::HandshakeAfterVerack;
use crate::heuristics::misbehaving_peer::MisbehavingPeer;
use crate::heuristics::ping_spammer::{PingSpammer, PingSpammerArgs};
use crate::heuristics::slow_block::{SlowBlock, SlowBlockArgs};
use crate::heuristics::small_ping_nonce::{SmallPingNonce, SmallPingNonceArgs};
use crate::heuristics::stale_tip::{StaleTip, StaleTipArgs};
use crate::heuristics::tx_relay_mismatch::TxRelayMismatch;
use crate::heuristics::{connection_event, inbound_message, Context, Heuristic, Peer, Peers};

/// How often heuristics get to act on time passing without any event.
const TICK_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server
    #[command(flatten)]
    pub nats: NatsArgs,

    #[command(flatten)]
    pub ping_spammer: PingSpammerArgs,

    #[command(flatten)]
    pub addr_spammer: AddrSpammerArgs,

    #[command(flatten)]
    pub small_ping_nonce: SmallPingNonceArgs,

    #[command(flatten)]
    pub slow_block: SlowBlockArgs,

    #[command(flatten)]
    pub stale_tip: StaleTipArgs,

    #[arg(short, long, default_value_t = shared::log::Level::Debug)]
    pub log_level: shared::log::Level,

    /// Remove peers not seen for this many seconds (prevents OOM on missed Close events)
    #[arg(long, default_value_t = 300)]
    pub peer_stale_secs: u64,
}

#[cfg(any(test, feature = "nats_integration_tests"))]
impl Args {
    /// Arguments with all heuristics at their default settings, connecting to
    /// the NATS server at `nats_address`. Tests start from this and change
    /// the settings they care about.
    pub fn for_tests(nats_address: &str) -> Self {
        Args {
            nats: NatsArgs {
                address: nats_address.to_string(),
                username: None,
                password: None,
                password_file: None,
            },
            ping_spammer: PingSpammerArgs::default(),
            addr_spammer: AddrSpammerArgs::default(),
            small_ping_nonce: SmallPingNonceArgs::default(),
            slow_block: SlowBlockArgs::default(),
            stale_tip: StaleTipArgs::default(),
            log_level: shared::log::Level::Trace,
            peer_stale_secs: 300,
        }
    }
}

/// The heuristics to run, built from the command line arguments.
fn build_heuristics(args: &Args) -> Vec<Box<dyn Heuristic>> {
    vec![
        Box::new(PingSpammer::new(args.ping_spammer.clone())),
        Box::new(AddrSpammer::new(args.addr_spammer.clone())),
        Box::new(MisbehavingPeer),
        Box::new(HandshakeAfterVerack::default()),
        Box::new(SmallPingNonce::new(args.small_ping_nonce.clone())),
        Box::new(TxRelayMismatch::default()),
        Box::new(SlowBlock::new(args.slow_block.clone())),
        Box::new(StaleTip::new(args.stale_tip.clone(), Instant::now())),
    ]
}

/// The peers we know about and the heuristics watching them.
struct State {
    peers: Peers,
    heuristics: Vec<Box<dyn Heuristic>>,
}

impl State {
    fn new(args: &Args) -> Self {
        State {
            peers: Peers::new(),
            heuristics: build_heuristics(args),
        }
    }

    /// Remembers the peer an event came from and when we last heard from it.
    /// Peers are picked up when their connection opens or when they send us
    /// a message, so a peer is known by the time Bitcoin Core complains
    /// about it.
    fn track_peer(&mut self, event: &Event, now: Instant) {
        let conn = match connection_event(event) {
            Some(connection_event::Event::Inbound(c)) => Some(&c.conn),
            Some(connection_event::Event::Outbound(c)) => Some(&c.conn),
            _ => None,
        };
        let (peer_id, addr) = match (inbound_message(event), conn) {
            (Some(msg), _) => (msg.meta.peer_id, &msg.meta.addr),
            (None, Some(conn)) => (conn.peer_id, &conn.addr),
            (None, None) => return,
        };
        let peer = self.peers.entry(peer_id).or_insert_with(|| Peer {
            addr: addr.clone(),
            last_seen: now,
        });
        peer.last_seen = now;
    }

    /// Forgets `peer_id` everywhere. If a heuristic had flagged the peer, a
    /// `PeerDisconnected` alert saying how long the peer stayed around after
    /// the first flag is appended to `out`.
    fn remove_peer(&mut self, peer_id: u64, addr: &str, now: Instant, out: &mut Vec<Alert>) {
        let addr = match self.peers.remove(&peer_id) {
            Some(peer) => peer.addr,
            None => addr.to_string(),
        };
        let first_alerted = self
            .heuristics
            .iter_mut()
            .filter_map(|h| h.on_peer_removed(peer_id))
            .min();
        if let Some(first_alerted) = first_alerted {
            out.push(Alert::PeerDisconnected {
                peer_id,
                addr,
                active_secs: now.duration_since(first_alerted).as_secs(),
            });
        }
    }

    /// Lets every heuristic act on time passing.
    fn tick(&mut self, now: Instant, out: &mut Vec<Alert>) {
        let ctx = Context {
            now,
            peers: &self.peers,
        };
        for heuristic in self.heuristics.iter_mut() {
            heuristic.on_tick(&ctx, out);
        }
    }

    /// Forgets peers we haven't heard from in `stale_after`.
    fn remove_stale_peers(&mut self, stale_after: Duration, now: Instant, out: &mut Vec<Alert>) {
        let stale: Vec<(u64, String)> = self
            .peers
            .iter()
            .filter(|(_, p)| now.duration_since(p.last_seen) > stale_after)
            .map(|(id, p)| (*id, p.addr.clone()))
            .collect();
        for (peer_id, addr) in stale {
            self.remove_peer(peer_id, &addr, now, out);
        }
    }
}

/// Connects to NATS, subscribes to all subjects, and dispatches each
/// received event to `handle_event`. Alerts are emitted through `alerter`
pub async fn run<A: Alerter>(
    args: Args,
    alerter: A,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    log::info!("starting alerts with {:?}", args);

    let nc = nats_util::prepare_connection(&args.nats)
        .context("preparing NATS connection")?
        .connect(&args.nats.address)
        .await
        .with_context(|| format!("connecting to NATS at {}", args.nats.address))?;

    let netmsg_sub = nc
        .subscribe(Subject::NetMsg.to_string())
        .await
        .context("subscribing to the NetMsg subject")?;
    let netconn_sub = nc
        .subscribe(Subject::NetConn.to_string())
        .await
        .context("subscribing to the NetConn subject")?;
    let validation_sub = nc
        .subscribe(Subject::Validation.to_string())
        .await
        .context("subscribing to the Validation subject")?;
    let mut sub = shared::futures::stream::select_all([netmsg_sub, netconn_sub, validation_sub]);
    log::info!("Connected to NATS-server at {}", args.nats.address);

    let mut state = State::new(&args);

    let stale_after = Duration::from_secs(args.peer_stale_secs);
    let mut cleanup_interval = shared::tokio::time::interval(stale_after);
    cleanup_interval.tick().await;
    let mut tick_interval = shared::tokio::time::interval(TICK_INTERVAL);
    tick_interval.tick().await;

    loop {
        shared::tokio::select! {
            _ = tick_interval.tick() => {
                let mut alerts = Vec::new();
                state.tick(Instant::now(), &mut alerts);
                emit_all(alerts, &alerter);
            }
            maybe_msg = sub.next() => {
                match maybe_msg {
                    Some(msg) => match Event::decode(msg.payload) {
                        Ok(event) => handle_event(event, &mut state, &alerter),
                        Err(e) => log::warn!("dropping undecodable NATS payload: {e}"),
                    },
                    None => break,
                }
            }
            _ = cleanup_interval.tick() => {
                let mut alerts = Vec::new();
                state.remove_stale_peers(stale_after, Instant::now(), &mut alerts);
                emit_all(alerts, &alerter);
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("alerts tool received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Hands one event to every heuristic and forgets peers whose connection closed.
fn handle_event(event: Event, state: &mut State, alerter: &impl Alerter) {
    let now = Instant::now();
    let mut alerts = Vec::new();

    state.track_peer(&event, now);

    let ctx = Context {
        now,
        peers: &state.peers,
    };
    for heuristic in state.heuristics.iter_mut() {
        heuristic.on_event(&event, &ctx, &mut alerts);
    }

    if let Some(connection_event::Event::Closed(closed)) = connection_event(&event) {
        state.remove_peer(closed.conn.peer_id, &closed.conn.addr, now, &mut alerts);
    }

    emit_all(alerts, alerter);
}

fn emit_all(alerts: Vec<Alert>, alerter: &impl Alerter) {
    for alert in alerts {
        alerter.emit(alert);
    }
}
