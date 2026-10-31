//! The heuristics the alerts tool evaluates. Each heuristic lives in its own
//! module, owns the state it needs, and produces `Alert`s through the
//! `Heuristic` trait. The event loop in `lib.rs` feeds every event to every
//! heuristic and tells them when a peer goes away.

use crate::alerter::Alert;
use shared::protobuf::ebpf_extractor::connection::connection_event;
use shared::protobuf::ebpf_extractor::ebpf::EbpfEvent;
use shared::protobuf::ebpf_extractor::message::MessageEvent;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub mod addr_spammer;
pub mod handshake_after_verack;
pub mod misbehaving_peer;
pub mod ping_spammer;
pub mod small_ping_nonce;
pub mod tx_relay_mismatch;

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
    use shared::protobuf::bitcoin_primitives::{address, Address, InventoryItem};
    use shared::protobuf::ebpf_extractor::connection::{connection_event, ConnectionEvent};
    use shared::protobuf::ebpf_extractor::ebpf::EbpfEvent;
    use shared::protobuf::ebpf_extractor::message::message_event::Msg;
    use shared::protobuf::ebpf_extractor::message::{Inv, MessageEvent, Metadata, Version};
    use shared::protobuf::ebpf_extractor::Ebpf;
    use shared::protobuf::event::event::PeerObserverEvent;
    use shared::protobuf::event::Event;

    pub const PEER_ADDR: &str = "1.2.3.4:8333";

    /// Wraps an ebpf-extractor event into an `Event` with a fixed timestamp.
    pub fn ebpf(ebpf_event: EbpfEvent) -> Event {
        Event {
            timestamp: 1_700_000_000_000,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf_event),
            })),
        }
    }

    /// A connection event.
    pub fn connection(event: connection_event::Event) -> Event {
        ebpf(EbpfEvent::Connection(ConnectionEvent {
            event: Some(event),
        }))
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

    /// An inbound `version` message from `peer_id` with the given relay flag.
    pub fn version(peer_id: u64, relay: bool) -> Event {
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
                timestamp: 0,
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
