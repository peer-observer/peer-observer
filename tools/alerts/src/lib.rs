#![cfg_attr(feature = "strict", deny(warnings))]

use shared::anyhow::{Context, Result};
use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::nats_subjects::Subject;
use shared::nats_util;
use shared::nats_util::NatsArgs;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::connection::connection_event;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::event::Event;
use shared::tokio::sync::watch;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub mod alerter;

pub use crate::alerter::{Alert, Alerter, LoggingAlerter, SpammerKind};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Arguments for the connection to the NATS server
    #[command(flatten)]
    pub nats: NatsArgs,

    /// Number of pings in the window before alerting
    #[arg(long, default_value_t = 3)]
    pub ping_threshold: usize,

    /// Sliding window size for ping detection (seconds)
    #[arg(long, default_value_t = 120)]
    pub ping_window_secs: u64,

    /// Number of addr/addrv2 messages in the window before alerting
    #[arg(long, default_value_t = 6)]
    pub addr_threshold: usize,

    /// Sliding window size for addr detection (seconds)
    #[arg(long, default_value_t = 60)]
    pub addr_window_secs: u64,

    #[arg(short, long, default_value_t = shared::log::Level::Debug)]
    pub log_level: shared::log::Level,

    /// Remove peers not seen for this many seconds (prevents OOM on missed Close events)
    #[arg(long, default_value_t = 300)]
    pub peer_stale_secs: u64,
}

#[derive(Default)]
struct AlertTypeState {
    timestamps: VecDeque<Instant>,
    alerted_at: Option<Instant>,
}

struct PeerState {
    ping: AlertTypeState,
    addr: AlertTypeState,
    last_seen: Instant,
    peer_addr: String,
}

impl PeerState {
    fn new(peer_addr: String, now: Instant) -> Self {
        PeerState {
            ping: AlertTypeState::default(),
            addr: AlertTypeState::default(),
            last_seen: now,
            peer_addr,
        }
    }

    /// Records a hit for `kind` and returns an `Alert` the first time the
    /// threshold is exceeded. After alerting once, subsequent hits are dropped
    /// and the function returns `None` without growing the sliding window
    fn check(
        &mut self,
        kind: SpammerKind,
        peer_id: u64,
        now: Instant,
        args: &Args,
    ) -> Option<Alert> {
        let (state, window_secs, threshold) = match kind {
            SpammerKind::Ping => (&mut self.ping, args.ping_window_secs, args.ping_threshold),
            SpammerKind::Addr => (&mut self.addr, args.addr_window_secs, args.addr_threshold),
        };

        if state.alerted_at.is_some() {
            return None;
        }

        state.timestamps.push_back(now);
        let window = Duration::from_secs(window_secs);
        while state
            .timestamps
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            state.timestamps.pop_front();
        }
        if state.timestamps.len() <= threshold {
            return None;
        }
        let count = state.timestamps.len();
        state.alerted_at = Some(now);

        Some(Alert::Spammer {
            kind,
            peer_id,
            addr: self.peer_addr.clone(),
            count,
            window_secs,
            threshold,
        })
    }
}

struct AlertState {
    peers: HashMap<u64, PeerState>,
}

impl AlertState {
    fn new() -> Self {
        AlertState {
            peers: HashMap::new(),
        }
    }
}

/// Builds a `PeerDisconnected` alert for peers that were previously flagged as
/// spammers, including how long they were active. Returns `None` for peers
/// that were never flagged so non-flagged disconnects stay silent
fn disconnect_alert(peer_id: u64, peer: &PeerState, now: Instant) -> Option<Alert> {
    let first_alerted = [peer.ping.alerted_at, peer.addr.alerted_at]
        .into_iter()
        .flatten()
        .min()?;
    Some(Alert::PeerDisconnected {
        peer_id,
        addr: peer.peer_addr.clone(),
        active_secs: now.duration_since(first_alerted).as_secs(),
    })
}

/// Removes peers that haven't sent any message in `stale_after`
/// Emits a `PeerDisconnected` alert for any flagged peers evicted this way
fn cleanup_stale_peers(
    state: &mut AlertState,
    stale_after: Duration,
    now: Instant,
    alerter: &impl Alerter,
) {
    let stale: Vec<u64> = state
        .peers
        .iter()
        .filter(|(_, p)| now.duration_since(p.last_seen) > stale_after)
        .map(|(id, _)| *id)
        .collect();
    for peer_id in stale {
        if let Some(peer) = state.peers.remove(&peer_id) {
            if let Some(alert) = disconnect_alert(peer_id, &peer, now) {
                alerter.emit(alert);
            }
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
    let mut sub = shared::futures::stream::select(netmsg_sub, netconn_sub);
    log::info!("Connected to NATS-server at {}", args.nats.address);

    let mut state = AlertState::new();

    let stale_after = Duration::from_secs(args.peer_stale_secs);
    let mut cleanup_interval = shared::tokio::time::interval(stale_after);
    cleanup_interval.tick().await;

    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {
                match maybe_msg {
                    Some(msg) => match Event::decode(msg.payload) {
                        Ok(event) => handle_event(event, &mut state, &args, &alerter),
                        Err(e) => log::warn!("dropping undecodable NATS payload: {e}"),
                    },
                    None => break,
                }
            }
            _ = cleanup_interval.tick() => {
                cleanup_stale_peers(&mut state, stale_after, Instant::now(), &alerter);
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

/// Routes a NATS event to the appropriate handler
fn handle_event(event: Event, state: &mut AlertState, args: &Args, alerter: &impl Alerter) {
    let now = Instant::now();
    if let Some(shared::protobuf::event::event::PeerObserverEvent::EbpfExtractor(ebpf)) =
        event.peer_observer_event
    {
        match ebpf.ebpf_event {
            Some(ebpf::EbpfEvent::Message(msg)) => handle_message(msg, state, args, alerter, now),
            Some(ebpf::EbpfEvent::Connection(conn)) => handle_connection(conn, state, now, alerter),
            _ => {}
        }
    }
}

/// Processes an inbound P2P message. Drops outbound messages and dispatches
/// to ping or addr spammer detection based on the message type
fn handle_message(
    msg: shared::protobuf::ebpf_extractor::message::MessageEvent,
    state: &mut AlertState,
    args: &Args,
    alerter: &impl Alerter,
    now: Instant,
) {
    if !msg.meta.inbound {
        return;
    }

    let peer_id = msg.meta.peer_id;
    let addr = &msg.meta.addr;

    let peer = state
        .peers
        .entry(peer_id)
        .or_insert_with(|| PeerState::new(addr.clone(), now));
    peer.last_seen = now;

    let kind = match msg.msg {
        Some(Msg::Ping(_)) => SpammerKind::Ping,
        Some(Msg::Addr(_)) | Some(Msg::Addrv2(_)) => SpammerKind::Addr,
        _ => return,
    };

    if let Some(alert) = peer.check(kind, peer_id, now, args) {
        alerter.emit(alert);
    }
}

/// Cleans up peer state when a connection closes and emits a
/// `PeerDisconnected` alert if the peer was previously flagged
fn handle_connection(
    conn: shared::protobuf::ebpf_extractor::connection::ConnectionEvent,
    state: &mut AlertState,
    now: Instant,
    alerter: &impl Alerter,
) {
    if let Some(connection_event::Event::Closed(c)) = conn.event {
        let peer_id = c.conn.peer_id;
        if let Some(peer) = state.peers.remove(&peer_id) {
            if let Some(alert) = disconnect_alert(peer_id, &peer, now) {
                alerter.emit(alert);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_args(ping_threshold: usize, addr_threshold: usize, window_secs: u64) -> Args {
        Args {
            nats: NatsArgs {
                address: "127.0.0.1:4222".to_string(),
                username: None,
                password: None,
                password_file: None,
            },
            ping_threshold,
            ping_window_secs: window_secs,
            addr_threshold,
            addr_window_secs: window_secs,
            log_level: shared::log::Level::Trace,
            peer_stale_secs: 300,
        }
    }

    fn make_peer(now: Instant) -> PeerState {
        PeerState::new("1.2.3.4:8333".to_string(), now)
    }

    fn unwrap_spammer(alert: Alert) -> (SpammerKind, u64, usize, u64, usize) {
        match alert {
            Alert::Spammer {
                kind,
                peer_id,
                count,
                window_secs,
                threshold,
                ..
            } => (kind, peer_id, count, window_secs, threshold),
            other => panic!("expected Alert::Spammer, got {other:?}"),
        }
    }

    #[test]
    fn below_threshold_no_alert() {
        let args = test_args(3, 3, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        // threshold=3 means "more than 3"; 3 hits must not fire
        for i in 0..3 {
            let now = t0 + Duration::from_millis(i);
            assert!(peer.check(SpammerKind::Ping, 1, now, &args).is_none());
        }
    }

    #[test]
    fn above_threshold_fires_once() {
        let args = test_args(3, 3, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        for i in 0..3 {
            peer.check(SpammerKind::Ping, 1, t0 + Duration::from_millis(i), &args);
        }
        let alert = peer
            .check(SpammerKind::Ping, 1, t0 + Duration::from_millis(4), &args)
            .expect("4th hit over threshold=3 must emit an alert");
        let (kind, peer_id, count, _, threshold) = unwrap_spammer(alert);
        assert_eq!(kind, SpammerKind::Ping);
        assert_eq!(peer_id, 1);
        assert_eq!(count, 4);
        assert_eq!(threshold, 3);
    }

    #[test]
    fn one_shot_no_retrigger() {
        let args = test_args(3, 3, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        // Cross the threshold
        for i in 0..4 {
            peer.check(SpammerKind::Ping, 1, t0 + Duration::from_millis(i), &args);
        }
        assert!(peer.ping.alerted_at.is_some());
        let len_at_alert = peer.ping.timestamps.len();

        // 10 more hits — none should alert, and the deque must not grow
        for i in 4..14 {
            assert!(peer
                .check(SpammerKind::Ping, 1, t0 + Duration::from_millis(i), &args)
                .is_none());
        }
        assert_eq!(
            peer.ping.timestamps.len(),
            len_at_alert,
            "deque must not grow after the one-shot alert fires"
        );
    }

    #[test]
    fn out_of_window_hits_dropped() {
        let args = test_args(3, 3, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        // Two hits at t0
        peer.check(SpammerKind::Ping, 1, t0, &args);
        peer.check(SpammerKind::Ping, 1, t0 + Duration::from_secs(1), &args);

        // Advance past the window (60s) so the first two fall out
        let later = t0 + Duration::from_secs(90);
        for i in 0..3 {
            assert!(peer
                .check(
                    SpammerKind::Ping,
                    1,
                    later + Duration::from_millis(i),
                    &args
                )
                .is_none());
        }
        assert_eq!(
            peer.ping.timestamps.len(),
            3,
            "only the 3 recent hits should remain in the sliding window"
        );
    }

    #[test]
    fn separate_counters_per_kind() {
        let args = test_args(3, 10, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        // 4 addr messages — below addr_threshold=10 — must not alert
        for i in 0..4 {
            assert!(peer
                .check(SpammerKind::Addr, 1, t0 + Duration::from_millis(i), &args)
                .is_none());
        }

        // 4 pings — above ping_threshold=3 — the 4th one must alert
        let mut ping_alerted = false;
        for i in 1..=4 {
            if peer
                .check(SpammerKind::Ping, 1, t0 + Duration::from_secs(i), &args)
                .is_some()
            {
                ping_alerted = true;
            }
        }
        assert!(ping_alerted, "4 pings with threshold=3 must alert");

        // Addr counter must still not have fired
        assert!(peer.addr.alerted_at.is_none());
    }

    #[test]
    fn addr_alert_carries_addr_window_fields() {
        let args = test_args(100, 2, 60);
        let t0 = Instant::now();
        let mut peer = make_peer(t0);

        for i in 0..2 {
            peer.check(SpammerKind::Addr, 7, t0 + Duration::from_millis(i), &args);
        }
        let alert = peer
            .check(SpammerKind::Addr, 7, t0 + Duration::from_millis(3), &args)
            .expect("3rd hit with addr_threshold=2 must alert");
        let (kind, _, count, window_secs, threshold) = unwrap_spammer(alert);
        assert_eq!(kind, SpammerKind::Addr);
        assert_eq!(window_secs, args.addr_window_secs);
        assert_eq!(threshold, args.addr_threshold);
        assert_eq!(count, 3);
    }
}
