#![cfg_attr(feature = "strict", deny(warnings))]

use shared::anyhow::{Context as _, Result};
use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::metricserver;
use shared::nats_subjects::Subject;
use shared::nats_util;
use shared::nats_util::NatsArgs;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::connection::connection_event;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use shared::tokio::sync::{oneshot, watch};
use shared::util;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub mod alerter;
pub mod heuristics;
pub mod metrics;

pub use crate::alerter::{Alert, Alerter, LoggingAlerter, SpammerKind};
use crate::heuristics::addr_spammer::{AddrSpammer, AddrSpammerArgs};
use crate::heuristics::address_harvester::{AddressHarvester, AddressHarvesterArgs};
use crate::heuristics::connection_cycling::{ConnectionCycling, ConnectionCyclingArgs};
use crate::heuristics::handshake_after_verack::HandshakeAfterVerack;
use crate::heuristics::high_ping_wait::{HighPingWait, HighPingWaitArgs};
use crate::heuristics::inbound_connection_drops::{
    InboundConnectionDrops, InboundConnectionDropsArgs,
};
use crate::heuristics::low_outbound_peers::{LowOutboundPeers, LowOutboundPeersArgs};
use crate::heuristics::misbehaving_burst::{MisbehavingBurst, MisbehavingBurstArgs};
use crate::heuristics::misbehaving_peer::MisbehavingPeer;
use crate::heuristics::netgroup_fleet::{NetgroupFleet, NetgroupFleetArgs};
use crate::heuristics::old_connection_drops::{OldConnectionDrops, OldConnectionDropsArgs};
use crate::heuristics::ping_spammer::{PingSpammer, PingSpammerArgs};
use crate::heuristics::repeated_getaddr::{RepeatedGetaddr, RepeatedGetaddrArgs};
use crate::heuristics::slow_block::{SlowBlock, SlowBlockArgs};
use crate::heuristics::small_ping_nonce::{SmallPingNonce, SmallPingNonceArgs};
use crate::heuristics::stale_tip::{StaleTip, StaleTipArgs};
use crate::heuristics::suspicious_peer::{SuspiciousPeer, SuspiciousPeerArgs};
use crate::heuristics::tx_relay_mismatch::TxRelayMismatch;
use crate::heuristics::tx_spy::{TxSpy, TxSpyArgs};
use crate::heuristics::unknown_messages::{UnknownMessages, UnknownMessagesArgs};
use crate::heuristics::version_time_offset::{VersionTimeOffset, VersionTimeOffsetArgs};
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
    pub unknown_messages: UnknownMessagesArgs,

    #[command(flatten)]
    pub version_time_offset: VersionTimeOffsetArgs,

    #[command(flatten)]
    pub tx_spy: TxSpyArgs,

    #[command(flatten)]
    pub repeated_getaddr: RepeatedGetaddrArgs,

    #[command(flatten)]
    pub slow_block: SlowBlockArgs,

    #[command(flatten)]
    pub stale_tip: StaleTipArgs,

    #[command(flatten)]
    pub connection_cycling: ConnectionCyclingArgs,

    #[command(flatten)]
    pub address_harvester: AddressHarvesterArgs,

    #[command(flatten)]
    pub misbehaving_burst: MisbehavingBurstArgs,

    #[command(flatten)]
    pub high_ping_wait: HighPingWaitArgs,

    #[command(flatten)]
    pub low_outbound_peers: LowOutboundPeersArgs,

    #[command(flatten)]
    pub netgroup_fleet: NetgroupFleetArgs,

    #[command(flatten)]
    pub inbound_connection_drops: InboundConnectionDropsArgs,

    #[command(flatten)]
    pub old_connection_drops: OldConnectionDropsArgs,

    #[command(flatten)]
    pub suspicious_peer: SuspiciousPeerArgs,

    /// The metrics server address the tool should listen on
    #[arg(short, long, default_value = "127.0.0.1:8283")]
    pub metrics_address: String,

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
            unknown_messages: UnknownMessagesArgs::default(),
            version_time_offset: VersionTimeOffsetArgs::default(),
            tx_spy: TxSpyArgs::default(),
            repeated_getaddr: RepeatedGetaddrArgs::default(),
            slow_block: SlowBlockArgs::default(),
            stale_tip: StaleTipArgs::default(),
            connection_cycling: ConnectionCyclingArgs::default(),
            address_harvester: AddressHarvesterArgs::default(),
            misbehaving_burst: MisbehavingBurstArgs::default(),
            high_ping_wait: HighPingWaitArgs::default(),
            low_outbound_peers: LowOutboundPeersArgs::default(),
            netgroup_fleet: NetgroupFleetArgs::default(),
            inbound_connection_drops: InboundConnectionDropsArgs::default(),
            old_connection_drops: OldConnectionDropsArgs::default(),
            suspicious_peer: SuspiciousPeerArgs::default(),
            // Port 0 lets the system pick a free port. `run` reports it.
            metrics_address: "127.0.0.1:0".to_string(),
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
        Box::new(UnknownMessages::new(args.unknown_messages.clone())),
        Box::new(VersionTimeOffset::new(args.version_time_offset.clone())),
        Box::new(TxSpy::new(args.tx_spy.clone())),
        Box::new(RepeatedGetaddr::new(args.repeated_getaddr.clone())),
        Box::new(SlowBlock::new(args.slow_block.clone())),
        Box::new(StaleTip::new(args.stale_tip.clone(), Instant::now())),
        Box::new(ConnectionCycling::new(args.connection_cycling.clone())),
        Box::new(AddressHarvester::new(args.address_harvester.clone())),
        Box::new(MisbehavingBurst::new(args.misbehaving_burst.clone())),
        Box::new(HighPingWait::new(args.high_ping_wait.clone())),
        Box::new(LowOutboundPeers::new(args.low_outbound_peers.clone())),
        Box::new(NetgroupFleet::new(args.netgroup_fleet.clone())),
        Box::new(InboundConnectionDrops::new(
            args.inbound_connection_drops.clone(),
        )),
        Box::new(OldConnectionDrops::new(args.old_connection_drops.clone())),
    ]
}

/// The peers we know about and the heuristics watching them.
struct State {
    peers: Peers,
    heuristics: Vec<Box<dyn Heuristic>>,
    /// The alert kinds that flagged each connected peer, with the address
    /// used in the metrics, so the series can be removed when it leaves.
    flagged: HashMap<u64, Vec<(&'static str, String)>>,
    /// Combines the per-peer alerts into one verdict per address.
    suspicious: SuspiciousPeer,
    metrics: metrics::Metrics,
}

impl State {
    fn new(args: &Args, metrics: metrics::Metrics) -> Self {
        State {
            peers: Peers::new(),
            heuristics: build_heuristics(args),
            flagged: HashMap::new(),
            suspicious: SuspiciousPeer::new(args.suspicious_peer.clone()),
            metrics,
        }
    }

    /// Counts the alerts on the metrics endpoint, remembers which peers they
    /// flag, adds a `SuspiciousPeer` verdict when an address has collected
    /// enough of them, and hands everything to the alerter.
    fn emit(&mut self, mut alerts: Vec<Alert>, alerter: &impl Alerter, now: Instant) {
        let verdicts: Vec<Alert> = alerts
            .iter()
            .filter_map(|alert| self.suspicious.on_alert(alert, &self.peers, now))
            .collect();
        alerts.extend(verdicts);
        for alert in alerts {
            self.metrics.count(&alert);
            let mut peer = None;
            if let Some((peer_id, addr)) = alert.flagged_peer() {
                let kinds = self.flagged.entry(peer_id).or_default();
                if !kinds.iter().any(|(name, _)| *name == alert.name()) {
                    self.metrics.peer_flagged(alert.name(), peer_id, addr);
                    kinds.push((alert.name(), addr.to_string()));
                }
                peer = self.peers.get(&peer_id);
            }
            alerter.emit(alert, peer);
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
            user_agent: None,
            network: None,
        });
        peer.last_seen = now;
        if let Some(conn) = conn {
            peer.network = Some(conn.network);
        }
        if let Some(msg) = inbound_message(event) {
            if let Some(Msg::Version(version)) = &msg.msg {
                peer.user_agent = Some(version.user_agent.clone());
            }
        }
    }

    /// Forgets `peer_id` everywhere. If a heuristic had flagged the peer, a
    /// `PeerDisconnected` alert saying how long the peer stayed around after
    /// the first flag is appended to `out`.
    fn remove_peer(&mut self, peer_id: u64, addr: &str, now: Instant, out: &mut Vec<Alert>) {
        let addr = match self.peers.remove(&peer_id) {
            Some(peer) => peer.addr,
            None => addr.to_string(),
        };
        for (name, flagged_addr) in self.flagged.remove(&peer_id).unwrap_or_default() {
            self.metrics.peer_unflagged(name, peer_id, &flagged_addr);
        }
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
        self.suspicious.prune(now);
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
/// and counted on the metrics endpoint. The address the metrics server
/// bound to is sent to `bound_addr_tx`, which tests use with port 0.
pub async fn run<A: Alerter>(
    args: Args,
    alerter: A,
    mut shutdown_rx: watch::Receiver<bool>,
    bound_addr_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    log::info!("starting alerts with {:?}", args);

    let metrics = metrics::Metrics::new();

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
    let rpc_sub = nc
        .subscribe(Subject::Rpc.to_string())
        .await
        .context("subscribing to the Rpc subject")?;
    let mut sub =
        shared::futures::stream::select_all([netmsg_sub, netconn_sub, validation_sub, rpc_sub]);
    log::info!("Connected to NATS-server at {}", args.nats.address);

    let metrics_addr = metricserver::start(&args.metrics_address, Some(metrics.registry.clone()))
        .context("starting metrics server")?;
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(metrics_addr);
    }
    metrics
        .runtime_start_timestamp
        .set(util::current_timestamp() as i64);

    let mut state = State::new(&args, metrics);

    let stale_after = Duration::from_secs(args.peer_stale_secs);
    let mut cleanup_interval = shared::tokio::time::interval(stale_after);
    cleanup_interval.tick().await;
    let mut tick_interval = shared::tokio::time::interval(TICK_INTERVAL);
    tick_interval.tick().await;

    loop {
        shared::tokio::select! {
            _ = tick_interval.tick() => {
                let now = Instant::now();
                let mut alerts = Vec::new();
                state.tick(now, &mut alerts);
                state.emit(alerts, &alerter, now);
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
                let now = Instant::now();
                let mut alerts = Vec::new();
                state.remove_stale_peers(stale_after, now, &mut alerts);
                state.emit(alerts, &alerter, now);
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

    state.emit(alerts, alerter, now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{message, version, PEER_ADDR};
    use shared::protobuf::ebpf_extractor::message::Ping;

    #[test]
    fn the_peer_registry_remembers_the_user_agent() {
        let args = Args::for_tests("127.0.0.1:4222");
        let mut state = State::new(&args, metrics::Metrics::new());
        let now = Instant::now();

        state.track_peer(&message(1, true, "ping", Msg::Ping(Ping { value: 1 })), now);
        let peer = state.peers.get(&1).expect("peer is tracked");
        assert_eq!(peer.addr, PEER_ADDR);
        assert_eq!(peer.user_agent, None);

        state.track_peer(&version(1, true), now);
        assert_eq!(
            state.peers.get(&1).unwrap().user_agent.as_deref(),
            Some("/test/")
        );
    }
}
