//! The heuristics the alerts tool evaluates. Each heuristic lives in its own
//! module, owns the state it needs, and produces `Alert`s through the
//! `Heuristic` trait. The event loop in `lib.rs` feeds every event to every
//! heuristic and tells them when a peer goes away.

use crate::alerter::Alert;
use shared::protobuf::ebpf_extractor::connection::connection_event;
use shared::protobuf::ebpf_extractor::ebpf::EbpfEvent;
use shared::protobuf::ebpf_extractor::message::MessageEvent;
use shared::protobuf::ebpf_extractor::validation::{validation_event, BlockConnected};
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::protobuf::rpc_extractor::rpc::RpcEvent;
use shared::protobuf::rpc_extractor::PeerInfos;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub mod addr_spammer;
pub mod handshake_after_verack;
pub mod high_ping_wait;
pub mod inbound_connection_drops;
pub mod misbehaving_burst;
pub mod misbehaving_peer;
pub mod old_connection_drops;
pub mod ping_spammer;
pub mod slow_block;
pub mod small_ping_nonce;
pub mod stale_tip;
pub mod tx_relay_mismatch;
pub mod unknown_messages;
pub mod version_time_offset;

/// What the tool knows about a peer, independent of any heuristic.
pub struct Peer {
    pub addr: String,
    pub last_seen: Instant,
}

/// All peers the tool currently tracks, by Bitcoin Core peer id.
pub type Peers = HashMap<u64, Peer>;

/// Information handed to a heuristic together with each event.
pub struct Context<'a> {
    /// The time the event was processed. Heuristics use this for windows and
    /// timers instead of calling `Instant::now()` themselves, which keeps
    /// them testable.
    pub now: Instant,
    /// The peers the tool currently knows about.
    pub peers: &'a Peers,
}

/// A rule that turns events into alerts.
pub trait Heuristic: Send {
    /// Looks at one event and appends any alerts it triggers to `out`.
    fn on_event(&mut self, event: &Event, ctx: &Context, out: &mut Vec<Alert>);

    /// Called about once a second, so heuristics can act on time passing
    /// without any event, for example when nothing has happened for too long.
    fn on_tick(&mut self, _ctx: &Context, _out: &mut Vec<Alert>) {}

    /// Tells the heuristic that `peer_id` disconnected or went stale so it
    /// can drop the state it keeps for the peer. Returns when this heuristic
    /// first alerted on the peer, if it did. The event loop uses this to report
    /// how long a flagged peer was around.
    fn on_peer_removed(&mut self, _peer_id: u64) -> Option<Instant> {
        None
    }
}

/// Returns the ebpf-extractor event wrapped in `event`, if it is one.
pub fn ebpf_event(event: &Event) -> Option<&EbpfEvent> {
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(e)) => e.ebpf_event.as_ref(),
        _ => None,
    }
}

/// Returns the P2P message in `event` if it is one we received from a peer.
pub fn inbound_message(event: &Event) -> Option<&MessageEvent> {
    match ebpf_event(event) {
        Some(EbpfEvent::Message(msg)) if msg.meta.inbound => Some(msg),
        _ => None,
    }
}

/// Returns the connection event in `event`, if it is one.
pub fn connection_event(event: &Event) -> Option<&connection_event::Event> {
    match ebpf_event(event) {
        Some(EbpfEvent::Connection(conn)) => conn.event.as_ref(),
        _ => None,
    }
}

/// Returns the block Bitcoin Core connected in `event`, if it is such an event.
pub fn block_connected(event: &Event) -> Option<&BlockConnected> {
    match ebpf_event(event) {
        Some(EbpfEvent::Validation(validation)) => match &validation.event {
            Some(validation_event::Event::BlockConnected(block)) => Some(block),
            None => None,
        },
        _ => None,
    }
}

/// Returns the getpeerinfo result in `event`, if it is one.
pub fn peer_infos(event: &Event) -> Option<&PeerInfos> {
    match &event.peer_observer_event {
        Some(PeerObserverEvent::RpcExtractor(rpc)) => match &rpc.rpc_event {
            Some(RpcEvent::PeerInfos(infos)) => Some(infos),
            _ => None,
        },
        _ => None,
    }
}

/// Timestamps of hits inside a sliding time window, oldest first.
#[derive(Default)]
pub struct SlidingWindow {
    hits: VecDeque<Instant>,
}

impl SlidingWindow {
    /// Records a hit at `now`, forgets hits older than `window`, and returns
    /// how many hits remain.
    pub fn record(&mut self, now: Instant, window: Duration) -> usize {
        self.hits.push_back(now);
        self.prune(now, window)
    }

    /// Forgets hits older than `window` and returns how many hits remain.
    pub fn prune(&mut self, now: Instant, window: Duration) -> usize {
        while self
            .hits
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            self.hits.pop_front();
        }
        self.hits.len()
    }

    pub fn len(&self) -> usize {
        self.hits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }
}

/// A sliding window over node-wide hits that reports once per episode: it
/// reports the first time the hit count exceeds the threshold and stays quiet
/// until the count has fallen back to the threshold or below.
pub struct ThresholdWindow {
    window: Duration,
    threshold: usize,
    hits: SlidingWindow,
    armed: bool,
    /// When the last episode was reported. A steady rate right around the
    /// threshold would otherwise be reported every time the count dips and
    /// climbs again, so a new report also needs a full window to have passed.
    reported_at: Option<Instant>,
}

impl ThresholdWindow {
    pub fn new(window: Duration, threshold: usize) -> Self {
        ThresholdWindow {
            window,
            threshold,
            hits: SlidingWindow::default(),
            armed: true,
            reported_at: None,
        }
    }

    /// Records a hit at `now`. Returns the hit count if this hit starts a new
    /// episode above the threshold, and `None` otherwise.
    pub fn record(&mut self, now: Instant) -> Option<usize> {
        let count = self.hits.record(now, self.window);
        if !self.armed || count <= self.threshold {
            return None;
        }
        if self
            .reported_at
            .is_some_and(|at| now.duration_since(at) < self.window)
        {
            return None;
        }
        self.armed = false;
        self.reported_at = Some(now);
        Some(count)
    }

    /// Forgets old hits and re-arms once the count is back at or below the
    /// threshold. Call this regularly so an episode ends even without hits.
    pub fn tick(&mut self, now: Instant) {
        if self.hits.prune(now, self.window) <= self.threshold {
            self.armed = true;
        }
    }

    /// True when no hits are left in the window and the last report is older
    /// than the window, so nothing is left to remember.
    pub fn is_idle(&self, now: Instant) -> bool {
        self.hits.is_empty()
            && self
                .reported_at
                .is_none_or(|at| now.duration_since(at) >= self.window)
    }
}

struct PeerWindow {
    hits: SlidingWindow,
    alerted_at: Option<Instant>,
}

/// Counts hits per peer inside a sliding window and reports a peer once, the
/// first time its hit count exceeds the threshold. Further hits of a reported
/// peer are dropped so its window stops growing.
pub struct PerPeerWindowCounter {
    window: Duration,
    threshold: usize,
    peers: HashMap<u64, PeerWindow>,
}

impl PerPeerWindowCounter {
    pub fn new(window: Duration, threshold: usize) -> Self {
        PerPeerWindowCounter {
            window,
            threshold,
            peers: HashMap::new(),
        }
    }

    /// Records a hit for `peer_id` at `now`. Returns the number of hits in the
    /// window the first time it exceeds the threshold, and `None` otherwise.
    pub fn hit(&mut self, peer_id: u64, now: Instant) -> Option<usize> {
        let peer = self.peers.entry(peer_id).or_insert_with(|| PeerWindow {
            hits: SlidingWindow::default(),
            alerted_at: None,
        });
        if peer.alerted_at.is_some() {
            return None;
        }
        let count = peer.hits.record(now, self.window);
        if count <= self.threshold {
            return None;
        }
        peer.alerted_at = Some(now);
        Some(count)
    }

    /// Forgets `peer_id` and returns when it was reported, if it was.
    pub fn remove(&mut self, peer_id: u64) -> Option<Instant> {
        self.peers.remove(&peer_id).and_then(|p| p.alerted_at)
    }

    #[cfg(test)]
    fn hits(&self, peer_id: u64) -> usize {
        self.peers.get(&peer_id).map_or(0, |p| p.hits.len())
    }
}

/// Builders for events used in the unit tests of the heuristics.
#[cfg(test)]
pub mod test_util {
    use shared::protobuf::bitcoin_primitives::inventory_item::Item;
    use shared::protobuf::bitcoin_primitives::ConnType;
    use shared::protobuf::bitcoin_primitives::{address, Address, InventoryItem};
    use shared::protobuf::ebpf_extractor::connection::{
        connection_event, ClosedConnection, Connection, ConnectionEvent, EvictedInboundConnection,
    };
    use shared::protobuf::ebpf_extractor::ebpf::EbpfEvent;
    use shared::protobuf::ebpf_extractor::message::message_event::Msg;
    use shared::protobuf::ebpf_extractor::message::{Inv, MessageEvent, Metadata, Version};
    use shared::protobuf::ebpf_extractor::validation::{
        validation_event, BlockConnected, ValidationEvent,
    };
    use shared::protobuf::ebpf_extractor::Ebpf;
    use shared::protobuf::event::event::PeerObserverEvent;
    use shared::protobuf::event::Event;
    use shared::protobuf::rpc_extractor::rpc::RpcEvent;
    use shared::protobuf::rpc_extractor::{PeerInfo, PeerInfos, Rpc};
    use std::collections::HashMap;

    pub const PEER_ADDR: &str = "1.2.3.4:8333";
    /// The UNIX timestamp, in seconds, every test event carries.
    pub const EVENT_TIMESTAMP_SECS: u64 = 1_700_000_000;

    /// Wraps an ebpf-extractor event into an `Event` with a fixed timestamp.
    pub fn ebpf(ebpf_event: EbpfEvent) -> Event {
        Event {
            timestamp: EVENT_TIMESTAMP_SECS * 1000,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf_event),
            })),
        }
    }

    /// Bitcoin Core connected a block at `height`. Its hash is the height
    /// repeated, and connecting it took `connection_time_ns`.
    pub fn block(height: i32, connection_time_ns: u64) -> Event {
        ebpf(EbpfEvent::Validation(ValidationEvent {
            event: Some(validation_event::Event::BlockConnected(BlockConnected {
                hash: vec![height as u8; 32],
                height,
                transactions: 10,
                inputs: 20,
                sigops: 30,
                connection_time: connection_time_ns,
            })),
        }))
    }

    /// Bitcoin Core closed the connection to `peer_id`, which it opened at
    /// the UNIX timestamp `time_established`.
    pub fn closed(peer_id: u64, conn_type: ConnType, time_established: u64) -> Event {
        connection(connection_event::Event::Closed(ClosedConnection {
            conn: Connection {
                peer_id,
                addr: PEER_ADDR.to_string(),
                conn_type: conn_type as i32,
                network: 1,
            },
            time_established,
        }))
    }

    /// Bitcoin Core evicted the inbound connection to `peer_id`.
    pub fn evicted(peer_id: u64) -> Event {
        connection(connection_event::Event::InboundEvicted(
            EvictedInboundConnection {
                conn: Connection {
                    peer_id,
                    addr: PEER_ADDR.to_string(),
                    conn_type: ConnType::Inbound as i32,
                    network: 1,
                },
                time_established: 0,
            },
        ))
    }

    /// A connection event.
    pub fn connection(event: connection_event::Event) -> Event {
        ebpf(EbpfEvent::Connection(ConnectionEvent {
            event: Some(event),
        }))
    }

    /// A getpeerinfo result listing `infos`.
    pub fn peer_infos_event(infos: Vec<PeerInfo>) -> Event {
        Event {
            timestamp: EVENT_TIMESTAMP_SECS * 1000,
            peer_observer_event: Some(PeerObserverEvent::RpcExtractor(Rpc {
                rpc_event: Some(RpcEvent::PeerInfos(PeerInfos { infos })),
            })),
        }
    }

    /// One getpeerinfo entry. Only the fields the heuristics look at are
    /// meaningful, the rest hold placeholder values.
    pub fn peer_info(id: u32, connection_type: &str, ping_wait_ms: f64) -> PeerInfo {
        PeerInfo {
            id,
            address: format!("10.0.0.{}:8333", id % 256),
            address_bind: "1.2.3.4:8333".to_string(),
            address_local: "1.2.3.4:8333".to_string(),
            network: "ipv4".to_string(),
            mapped_as: 0,
            services: "0000000000000409".to_string(),
            relay_transactions: true,
            last_send: 0,
            last_received: 0,
            last_transaction: 0,
            last_block: 0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_time: 0,
            time_offset: 0,
            ping_time: 50.0,
            minimum_ping: 40.0,
            ping_wait: ping_wait_ms,
            version: 70016,
            subversion: "/test/".to_string(),
            inbound: connection_type == "inbound",
            bip152_hb_to: false,
            bip152_hb_from: false,
            starting_height: 0,
            synced_headers: 0,
            synced_blocks: 0,
            inflight: vec![],
            addr_relay_enabled: true,
            addr_processed: 0,
            addr_rate_limited: 0,
            permissions: vec![],
            minfeefilter: 0.0,
            bytes_sent_per_message: HashMap::new(),
            bytes_received_per_message: HashMap::new(),
            connection_type: connection_type.to_string(),
            transport_protocol_type: "v2".to_string(),
            inv_to_send: 0,
        }
    }

    /// A P2P message `msg` exchanged with `peer_id`.
    pub fn message(peer_id: u64, inbound: bool, command: &str, msg: Msg) -> Event {
        ebpf(EbpfEvent::Message(MessageEvent {
            meta: Metadata {
                peer_id,
                addr: PEER_ADDR.to_string(),
                conn_type: 1,
                command: command.to_string(),
                inbound,
                size: 0,
            },
            msg: Some(msg),
        }))
    }

    /// An inbound `version` message from `peer_id` with the given relay flag,
    /// sent with a clock that agrees with ours.
    pub fn version(peer_id: u64, relay: bool) -> Event {
        version_at(peer_id, relay, EVENT_TIMESTAMP_SECS as i64)
    }

    /// An inbound `version` message from `peer_id` carrying `timestamp` as
    /// the sender's time.
    pub fn version_at(peer_id: u64, relay: bool, timestamp: i64) -> Event {
        let address = || Address {
            timestamp: 0,
            services: 1,
            port: 8333,
            address: Some(address::Address::Ipv4("127.0.0.1".to_string())),
        };
        message(
            peer_id,
            true,
            "version",
            Msg::Version(Version {
                version: 70016,
                services: 1,
                timestamp,
                receiver: address(),
                sender: address(),
                nonce: 1,
                user_agent: "/test/".to_string(),
                start_height: 0,
                relay,
            }),
        )
    }

    /// An inbound `inv` message from `peer_id` announcing `items`.
    pub fn inv(peer_id: u64, items: Vec<Item>) -> Event {
        let items = items
            .into_iter()
            .map(|item| InventoryItem { item: Some(item) })
            .collect();
        message(peer_id, true, "inv", Msg::Inv(Inv { items }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_stays_silent_up_to_threshold() {
        let mut counter = PerPeerWindowCounter::new(Duration::from_secs(60), 3);
        let t0 = Instant::now();
        // threshold=3 means "more than 3": 3 hits must not report
        for i in 0..3 {
            assert_eq!(counter.hit(1, t0 + Duration::from_millis(i)), None);
        }
        assert_eq!(counter.hit(1, t0 + Duration::from_millis(4)), Some(4));
    }

    #[test]
    fn counter_reports_a_peer_once() {
        let mut counter = PerPeerWindowCounter::new(Duration::from_secs(60), 3);
        let t0 = Instant::now();
        for i in 0..4 {
            counter.hit(1, t0 + Duration::from_millis(i));
        }
        let hits_at_report = counter.hits(1);
        for i in 4..14 {
            assert_eq!(counter.hit(1, t0 + Duration::from_millis(i)), None);
        }
        assert_eq!(
            counter.hits(1),
            hits_at_report,
            "hits must not pile up after the peer was reported"
        );
        assert_eq!(counter.remove(1), Some(t0 + Duration::from_millis(3)));
    }

    #[test]
    fn counter_forgets_hits_outside_the_window() {
        let mut counter = PerPeerWindowCounter::new(Duration::from_secs(60), 3);
        let t0 = Instant::now();
        counter.hit(1, t0);
        counter.hit(1, t0 + Duration::from_secs(1));

        let later = t0 + Duration::from_secs(90);
        for i in 0..3 {
            assert_eq!(counter.hit(1, later + Duration::from_millis(i)), None);
        }
        assert_eq!(counter.hits(1), 3, "only the three recent hits remain");
    }

    #[test]
    fn threshold_window_reports_once_per_episode() {
        let mut window = ThresholdWindow::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        assert_eq!(window.record(t0), None);
        assert_eq!(window.record(t0), None);
        assert_eq!(window.record(t0), Some(3));
        assert_eq!(window.record(t0), None, "the episode is still running");

        // Still above the threshold after pruning: stays quiet
        window.tick(t0 + Duration::from_secs(10));
        assert_eq!(window.record(t0 + Duration::from_secs(10)), None);

        // All hits fell out of the window: a new episode can start
        window.tick(t0 + Duration::from_secs(100));
        assert_eq!(window.record(t0 + Duration::from_secs(100)), None);
        assert_eq!(window.record(t0 + Duration::from_secs(100)), None);
        assert_eq!(window.record(t0 + Duration::from_secs(100)), Some(3));
    }

    #[test]
    fn threshold_window_reports_a_steady_rate_once_per_window() {
        let mut window = ThresholdWindow::new(Duration::from_secs(60), 1);
        let t0 = Instant::now();
        // Two hits report, then one ages out and one new arrives, over and
        // over: the count flaps around the threshold but is reported once
        assert_eq!(window.record(t0), None);
        assert_eq!(window.record(t0 + Duration::from_secs(1)), Some(2));
        for s in [40, 50, 55, 59] {
            window.tick(t0 + Duration::from_secs(s));
            assert_eq!(window.record(t0 + Duration::from_secs(s)), None);
        }
        assert!(
            !window.is_idle(t0 + Duration::from_secs(59)),
            "a recent report is worth remembering"
        );
        // A full window after the report it may be reported again
        window.tick(t0 + Duration::from_secs(130));
        assert_eq!(window.record(t0 + Duration::from_secs(130)), None);
        assert_eq!(window.record(t0 + Duration::from_secs(131)), Some(2));
    }

    #[test]
    fn counter_keeps_peers_apart() {
        let mut counter = PerPeerWindowCounter::new(Duration::from_secs(60), 1);
        let t0 = Instant::now();
        assert_eq!(counter.hit(1, t0), None);
        assert_eq!(counter.hit(2, t0), None);
        assert_eq!(counter.hit(1, t0), Some(2));
        assert_eq!(counter.remove(2), None, "peer 2 was never reported");
        assert_eq!(counter.remove(3), None, "unknown peers are fine to remove");
    }
}
