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

pub use crate::alerter::{Alert, Alerter, LoggingAlerter, PeerFlag, SpammerKind};

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

    /// Initial token seed for a peer's addr/addrv2 entry bucket. Mirrors Core's
    /// per-peer starting bucket (1.0, "permit self-announcement")
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    pub addr_entries_initial_tokens: u64,

    /// Token bucket capacity: the refill ceiling for addr/addrv2 entries. Mirrors
    /// Core's MAX_ADDR_PROCESSING_TOKEN_BUCKET (1000); the bucket refills up to
    /// this
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    pub addr_entries_bucket_capacity: u64,

    /// Token refill rate for addr/addrv2 entries (entries per second). Mirrors
    /// Core's MAX_ADDR_RATE_PER_SECOND (0.1, i.e. one entry every 10 seconds)
    #[arg(long, default_value_t = 0.1, value_parser = parse_non_negative_finite)]
    pub addr_entries_rate_per_sec: f64,

    /// Number of rate-limited addr/addrv2 entries before alerting
    #[arg(long, default_value_t = 20)]
    pub addr_entries_threshold: u64,

    #[arg(short, long, default_value_t = shared::log::Level::Debug)]
    pub log_level: shared::log::Level,

    /// Remove peers not seen for this many seconds (prevents OOM on missed Close events)
    #[arg(long, default_value_t = 300)]
    pub peer_stale_secs: u64,
}

/// Clap value parser: accepts a finite float greater than or equal to 0
fn parse_non_negative_finite(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|e| format!("{e}"))?;
    if v.is_finite() && v >= 0.0 {
        Ok(v)
    } else {
        Err(format!("must be a finite number >= 0, got {v}"))
    }
}

#[derive(Default)]
struct AlertTypeState {
    timestamps: VecDeque<Instant>,
    alerted_at: Option<Instant>,
}

/// Token bucket tracking addr/addrv2 entries, modeled on addr rate limiting
/// The bucket starts at the configured seed and refills over time up to the
/// capacity; entries that exceed the available tokens are counted as `rate_limited`
struct AddrEntriesState {
    tokens: f64,
    last_update: Instant,
    rate_limited: u64,
    getaddr_requests_sent: u64,
    alerted_at: Option<Instant>,
}

struct PeerState {
    ping: AlertTypeState,
    addr: AlertTypeState,
    addr_entries: AddrEntriesState,
    last_seen: Instant,
    peer_addr: String,
}

impl PeerState {
    fn new(peer_addr: String, now: Instant, addr_entries_initial_tokens: u64) -> Self {
        PeerState {
            ping: AlertTypeState::default(),
            addr: AlertTypeState::default(),
            addr_entries: AddrEntriesState {
                tokens: addr_entries_initial_tokens as f64,
                last_update: now,
                rate_limited: 0,
                getaddr_requests_sent: 0,
                alerted_at: None,
            },
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

    /// Models Core's response allowance for an outbound GETADDR: accept an
    /// additional MAX_ADDR_TO_SEND-style burst beyond the regular refill cap
    fn record_getaddr_sent(&mut self, args: &Args) {
        self.addr_entries.tokens += args.addr_entries_bucket_capacity as f64;
        self.addr_entries.getaddr_requests_sent =
            self.addr_entries.getaddr_requests_sent.saturating_add(1);
    }

    /// Feeds `entries` (the number of addresses in an addr/addrv2 message) into
    /// the per-peer token bucket. Refills the bucket for elapsed time, consumes
    /// one token per entry, and counts any entry beyond the bucket as
    /// rate-limited. Returns an `Alert` the first time the cumulative
    /// rate-limited count exceeds the threshold; one-shot afterwards
    fn check_addr_entries(
        &mut self,
        peer_id: u64,
        entries: usize,
        now: Instant,
        args: &Args,
    ) -> Option<Alert> {
        let state = &mut self.addr_entries;
        if state.alerted_at.is_some() {
            return None;
        }

        let capacity = args.addr_entries_bucket_capacity as f64;
        if state.tokens < capacity {
            let elapsed = now.duration_since(state.last_update).as_secs_f64();
            state.tokens = (state.tokens + elapsed * args.addr_entries_rate_per_sec).min(capacity);
        }
        state.last_update = now;

        // Consume one token per entry: process as many entries as
        // whole tokens allow, count the rest as rate-limited, and keep the
        // fractional token remainder for the next message
        let entries = entries as f64;
        let processed = entries.min(state.tokens.floor());
        state.rate_limited = state
            .rate_limited
            .saturating_add((entries - processed) as u64);
        state.tokens -= processed;

        if state.rate_limited <= args.addr_entries_threshold {
            return None;
        }
        state.alerted_at = Some(now);

        Some(Alert::AddrEntriesSpammer {
            peer_id,
            addr: self.peer_addr.clone(),
            rate_limited: state.rate_limited,
            threshold: args.addr_entries_threshold,
            bucket_capacity: args.addr_entries_bucket_capacity,
            rate_per_sec: args.addr_entries_rate_per_sec,
            getaddr_requests_sent: state.getaddr_requests_sent,
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
    // Keep this list in the canonical display order. Using the same source for
    // both the duration and flags prevents the two from drifting apart as new
    // peer heuristics are added.
    let flags_and_times = [
        (PeerFlag::PingSpammer, peer.ping.alerted_at),
        (PeerFlag::AddrSpammer, peer.addr.alerted_at),
        (PeerFlag::AddrEntriesSpammer, peer.addr_entries.alerted_at),
    ];
    let first_alerted = flags_and_times
        .iter()
        .filter_map(|(_, alerted_at)| *alerted_at)
        .min()?;
    let flags = flags_and_times
        .into_iter()
        .filter_map(|(flag, alerted_at)| alerted_at.map(|_| flag))
        .collect();

    Some(Alert::PeerDisconnected {
        peer_id,
        addr: peer.peer_addr.clone(),
        active_secs: now.duration_since(first_alerted).as_secs(),
        flags,
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

/// Processes P2P messages relevant to alerts. Outbound GETADDR messages add
/// Core-style response allowance; other outbound messages are ignored.
fn handle_message(
    msg: shared::protobuf::ebpf_extractor::message::MessageEvent,
    state: &mut AlertState,
    args: &Args,
    alerter: &impl Alerter,
    now: Instant,
) {
    let peer_id = msg.meta.peer_id;
    let addr = &msg.meta.addr;

    if !msg.meta.inbound {
        if matches!(&msg.msg, Some(Msg::Getaddr(_))) {
            let peer = state.peers.entry(peer_id).or_insert_with(|| {
                PeerState::new(addr.clone(), now, args.addr_entries_initial_tokens)
            });
            peer.last_seen = now;
            peer.record_getaddr_sent(args);
        }
        return;
    }

    let peer = state
        .peers
        .entry(peer_id)
        .or_insert_with(|| PeerState::new(addr.clone(), now, args.addr_entries_initial_tokens));
    peer.last_seen = now;

    // addr/addrv2 feed two distinct heuristics: the message-count sliding window
    // (`check`) and the entry-count token bucket (`check_addr_entries`)
    let (kind, addr_entries) = match &msg.msg {
        Some(Msg::Ping(_)) => (SpammerKind::Ping, None),
        Some(Msg::Addr(a)) => (SpammerKind::Addr, Some(a.addresses.len())),
        Some(Msg::Addrv2(a)) => (SpammerKind::Addr, Some(a.addresses.len())),
        _ => return,
    };

    if let Some(alert) = peer.check(kind, peer_id, now, args) {
        alerter.emit(alert);
    }
    if let Some(entries) = addr_entries {
        if let Some(alert) = peer.check_addr_entries(peer_id, entries, now, args) {
            alerter.emit(alert);
        }
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
            addr_entries_initial_tokens: 1000,
            addr_entries_bucket_capacity: 1000,
            addr_entries_rate_per_sec: 0.1,
            addr_entries_threshold: 1000,
            log_level: shared::log::Level::Trace,
            peer_stale_secs: 300,
        }
    }

    /// Like test_args but pins the token-bucket knobs for addr-entries tests.
    /// Capacity is pinned equal to the seed so these focused tests exercise a
    /// bucket that starts full; the seed-below-capacity behavior has its own test
    fn entries_args(initial_tokens: u64, rate_per_sec: f64, threshold: u64) -> Args {
        Args {
            addr_entries_initial_tokens: initial_tokens,
            addr_entries_bucket_capacity: initial_tokens,
            addr_entries_rate_per_sec: rate_per_sec,
            addr_entries_threshold: threshold,
            ..test_args(100, 100, 60)
        }
    }

    fn make_peer(now: Instant) -> PeerState {
        PeerState::new("1.2.3.4:8333".to_string(), now, 1000)
    }

    /// Builds a peer whose entry bucket starts at exactly `initial_tokens`,
    /// allowing fractional runtime states (e.g. a partially drained bucket) that
    /// the integer CLI capacity can't express directly
    fn make_peer_with_tokens(now: Instant, initial_tokens: f64) -> PeerState {
        let mut peer = PeerState::new("1.2.3.4:8333".to_string(), now, 0);
        peer.addr_entries.tokens = initial_tokens;
        peer
    }

    #[test]
    fn disconnect_alert_is_none_for_unflagged_peer() {
        let now = Instant::now();
        let peer = make_peer(now);

        assert!(disconnect_alert(1, &peer, now + Duration::from_secs(10)).is_none());
    }

    #[test]
    fn disconnect_alert_includes_all_flags_and_uses_first_alert_time() {
        let t0 = Instant::now();
        let mut peer = make_peer(t0);
        peer.ping.alerted_at = Some(t0 + Duration::from_secs(2));
        peer.addr.alerted_at = Some(t0 + Duration::from_secs(4));
        peer.addr_entries.alerted_at = Some(t0 + Duration::from_secs(6));

        assert_eq!(
            disconnect_alert(7, &peer, t0 + Duration::from_secs(10)),
            Some(Alert::PeerDisconnected {
                peer_id: 7,
                addr: "1.2.3.4:8333".to_string(),
                active_secs: 8,
                flags: vec![
                    PeerFlag::PingSpammer,
                    PeerFlag::AddrSpammer,
                    PeerFlag::AddrEntriesSpammer,
                ],
            })
        );
    }

    fn unwrap_addr_entries(alert: Alert) -> (u64, u64, u64, u64) {
        match alert {
            Alert::AddrEntriesSpammer {
                peer_id,
                rate_limited,
                threshold,
                getaddr_requests_sent,
                ..
            } => (peer_id, rate_limited, threshold, getaddr_requests_sent),
            other => panic!("expected Alert::AddrEntriesSpammer, got {other:?}"),
        }
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

    #[test]
    fn addr_entries_burst_within_capacity_no_alert() {
        // seed=10, no refill, threshold=5: a single 10-entry message fills but
        // does not exceed the bucket, so nothing is rate-limited
        let args = entries_args(10, 0.0, 5);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 10.0);

        assert!(peer.check_addr_entries(1, 10, t0, &args).is_none());
        assert_eq!(peer.addr_entries.rate_limited, 0);
        assert_eq!(peer.addr_entries.tokens, 0.0);
    }

    #[test]
    fn addr_entries_sustained_flood_alerts() {
        // seed=10, no refill, threshold=5: entries beyond the bucket accumulate
        // as rate-limited and fire once the cumulative count passes the threshold
        let args = entries_args(10, 0.0, 5);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 10.0);

        // Drain the bucket (rate_limited still 0)
        assert!(peer.check_addr_entries(1, 10, t0, &args).is_none());
        // 4 over-rate entries: rate_limited=4, still <= threshold
        assert!(peer
            .check_addr_entries(1, 4, t0 + Duration::from_millis(1), &args)
            .is_none());
        assert_eq!(peer.addr_entries.rate_limited, 4);
        // 4 more: rate_limited=8 > 5 -> alert
        let alert = peer
            .check_addr_entries(1, 4, t0 + Duration::from_millis(2), &args)
            .expect("cumulative rate-limited entries over threshold must alert");
        let (peer_id, rate_limited, threshold, getaddr_requests_sent) = unwrap_addr_entries(alert);
        assert_eq!(peer_id, 1);
        assert_eq!(rate_limited, 8);
        assert_eq!(threshold, 5);
        assert_eq!(getaddr_requests_sent, 0);
    }

    #[test]
    fn addr_entries_refill_replenishes_tokens() {
        // seed=10, refill 1 entry/s, threshold=0 (alert on first rate-limited
        // entry). Draining then waiting refills the bucket so a later message of
        // the same size is fully covered and never rate-limited
        let args = entries_args(10, 1.0, 0);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 10.0);

        // Drain to 0 (threshold=0 but rate_limited is still 0 -> no alert)
        assert!(peer.check_addr_entries(1, 10, t0, &args).is_none());
        assert_eq!(peer.addr_entries.rate_limited, 0);

        // 5s later: +5 tokens; a 5-entry message is fully covered
        assert!(peer
            .check_addr_entries(1, 5, t0 + Duration::from_secs(5), &args)
            .is_none());
        assert_eq!(peer.addr_entries.rate_limited, 0);

        // Refill is capped at the seed: after a long gap tokens never exceed capacity
        assert!(peer
            .check_addr_entries(1, 0, t0 + Duration::from_secs(10_000), &args)
            .is_none());
        assert_eq!(peer.addr_entries.tokens, 10.0);
    }

    #[test]
    fn addr_entries_one_shot_no_retrigger() {
        // seed=1 (the smallest CLI-reachable capacity), no refill, threshold=0:
        // the first 3-entry message processes 1 and rate-limits 2 (> threshold),
        // firing once; subsequent messages are dropped without changing rate_limited
        let args = entries_args(1, 0.0, 0);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1.0);

        let alert = peer
            .check_addr_entries(9, 3, t0, &args)
            .expect("3 entries against a 1-token bucket and threshold 0 must alert");
        let (_, rate_limited, _, getaddr_requests_sent) = unwrap_addr_entries(alert);
        assert_eq!(rate_limited, 2);
        assert_eq!(getaddr_requests_sent, 0);

        // Further messages must not re-alert, and rate_limited must stay frozen
        for i in 1..5 {
            assert!(peer
                .check_addr_entries(9, 5, t0 + Duration::from_millis(i), &args)
                .is_none());
        }
        assert_eq!(peer.addr_entries.rate_limited, 2);
    }

    #[test]
    fn addr_entries_preserves_fractional_remainder() {
        // bucket seeded at 1.9 tokens (a drained/partially-refilled runtime
        // state), capacity 2, no refill: 2 entries process one whole token (1)
        // and rate-limit one, keeping the 0.9 fractional remainder (Core-style),
        // instead of zeroing the bucket
        let args = entries_args(2, 0.0, 100);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1.9);

        assert!(peer.check_addr_entries(1, 2, t0, &args).is_none());
        assert_eq!(peer.addr_entries.rate_limited, 1);
        assert!(
            (peer.addr_entries.tokens - 0.9).abs() < 1e-9,
            "expected ~0.9 tokens left, got {}",
            peer.addr_entries.tokens
        );
    }

    #[test]
    fn addr_entries_single_oversized_message_alerts() {
        // Core-faithful seed: the bucket starts at 1 even though its capacity is
        // 1000 (the MAX_ADDR_TO_SEND burst Core only grants after an outbound
        // GETADDR). A single 1000-entry addr processes 1 and rate-limits 999
        // (> threshold), so one oversized message alerts — the case a bucket
        // seeded at its full capacity would have missed
        let args = Args {
            addr_entries_initial_tokens: 1,
            addr_entries_bucket_capacity: 1000,
            addr_entries_rate_per_sec: 0.0,
            addr_entries_threshold: 20,
            ..test_args(100, 100, 60)
        };
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1.0);

        let alert = peer
            .check_addr_entries(1, 1000, t0, &args)
            .expect("a single 1000-entry addr against a seed-1 bucket must alert");
        let (_, rate_limited, threshold, getaddr_requests_sent) = unwrap_addr_entries(alert);
        assert_eq!(rate_limited, 999);
        assert_eq!(threshold, 20);
        assert_eq!(getaddr_requests_sent, 0);
    }

    #[test]
    fn addr_entries_getaddr_allows_expected_response() {
        let args = Args {
            addr_entries_initial_tokens: 1,
            addr_entries_bucket_capacity: 1000,
            addr_entries_rate_per_sec: 0.0,
            addr_entries_threshold: 20,
            ..test_args(100, 100, 60)
        };
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1.0);

        peer.record_getaddr_sent(&args);
        assert_eq!(peer.addr_entries.getaddr_requests_sent, 1);
        assert_eq!(peer.addr_entries.tokens, 1001.0);

        assert!(peer
            .check_addr_entries(1, 1000, t0 + Duration::from_millis(1), &args)
            .is_none());
        assert_eq!(peer.addr_entries.rate_limited, 0);
        assert_eq!(peer.addr_entries.tokens, 1.0);
    }

    #[test]
    fn addr_entries_getaddr_tokens_can_exceed_capacity_without_clamping() {
        let args = entries_args(1000, 1.0, 1000);
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1000.0);

        peer.record_getaddr_sent(&args);
        assert_eq!(peer.addr_entries.tokens, 2000.0);

        assert!(peer
            .check_addr_entries(1, 0, t0 + Duration::from_secs(60), &args)
            .is_none());
        assert_eq!(peer.addr_entries.tokens, 2000.0);
    }

    #[test]
    fn addr_entries_alerts_after_getaddr_response_excess() {
        let args = Args {
            addr_entries_initial_tokens: 1,
            addr_entries_bucket_capacity: 1000,
            addr_entries_rate_per_sec: 0.0,
            addr_entries_threshold: 20,
            ..test_args(100, 100, 60)
        };
        let t0 = Instant::now();
        let mut peer = make_peer_with_tokens(t0, 1.0);

        peer.record_getaddr_sent(&args);
        assert!(peer
            .check_addr_entries(1, 1000, t0 + Duration::from_millis(1), &args)
            .is_none());

        let alert = peer
            .check_addr_entries(1, 30, t0 + Duration::from_millis(2), &args)
            .expect("entries beyond the GETADDR allowance must still alert");
        let (_, rate_limited, threshold, getaddr_requests_sent) = unwrap_addr_entries(alert);
        assert_eq!(rate_limited, 29);
        assert_eq!(threshold, 20);
        assert_eq!(getaddr_requests_sent, 1);
    }

    #[test]
    fn rejects_invalid_entry_counts() {
        // The seed and the capacity are both entry counts (u64 >= 1): negatives,
        // zero, fractions and non-numbers must be rejected so the bucket can't be
        // configured into a state that silently rate-limits every entry
        assert!(Args::try_parse_from(["alerts", "--addr-entries-initial-tokens", "-1"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-initial-tokens", "0"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-initial-tokens", "0.5"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-initial-tokens", "nan"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-initial-tokens", "inf"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-bucket-capacity", "0"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-bucket-capacity", "-1"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-bucket-capacity", "0.5"]).is_err());
    }

    #[test]
    fn rejects_invalid_entry_rates() {
        // Exercise the custom f64 parser directly so failures come from
        // parse_non_negative_finite rather than clap's argument splitting.
        assert!(parse_non_negative_finite("-0.1").is_err());
        assert!(parse_non_negative_finite("nan").is_err());
        assert!(parse_non_negative_finite("inf").is_err());
        assert!(parse_non_negative_finite("-inf").is_err());

        assert!(Args::try_parse_from(["alerts", "--addr-entries-rate-per-sec=-0.1"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-rate-per-sec=nan"]).is_err());
        assert!(Args::try_parse_from(["alerts", "--addr-entries-rate-per-sec=inf"]).is_err());
    }

    #[test]
    fn parses_valid_entry_args() {
        assert_eq!(parse_non_negative_finite("0").expect("zero is valid"), 0.0);
        assert_eq!(
            parse_non_negative_finite("0.1").expect("fractional rate is valid"),
            0.1
        );

        assert!(Args::try_parse_from([
            "alerts",
            "--addr-entries-initial-tokens",
            "1",
            "--addr-entries-bucket-capacity",
            "2000",
            "--addr-entries-rate-per-sec",
            "0"
        ])
        .is_ok());
    }
}
