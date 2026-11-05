#![cfg(feature = "nats_integration_tests")]

use alerts::{alerter::IntegrationTestAlerter, Alert, Args, PeerFlag, SpammerKind};

use shared::{
    anyhow,
    async_nats::ConnectError,
    log,
    nats_subjects::Subject,
    nats_util,
    prost::Message,
    protobuf::{
        bitcoin_primitives::Address,
        ebpf_extractor::{
            connection::{self, ClosedConnection, Connection, ConnectionEvent},
            ebpf,
            message::{self, message_event::Msg, Addr, AddrV2, Metadata, Ping},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
    },
    testing::{nats_publisher::NatsPublisherForTesting, nats_server::NatsServerForTesting},
    tokio::{
        self,
        sync::{mpsc::UnboundedReceiver, watch},
        time::{sleep, timeout},
    },
};

use std::time::Duration;

struct AlertSettingsInTest {
    ping_threshold: usize,
    ping_window_secs: u64,
    addr_threshold: usize,
    addr_window_secs: u64,
    addr_entries_initial_tokens: u64,
    addr_entries_bucket_capacity: u64,
    addr_entries_rate_per_sec: f64,
    addr_entries_threshold: u64,
    peer_stale_secs: u64,
}

impl Default for AlertSettingsInTest {
    fn default() -> Self {
        Self {
            ping_threshold: 10,
            ping_window_secs: 60,
            addr_threshold: 5,
            addr_window_secs: 60,
            // Token bucket large enough that the message-count tests (which send
            // zero-entry messages) never trip the entry heuristic
            addr_entries_initial_tokens: 1000,
            addr_entries_bucket_capacity: 1000,
            addr_entries_rate_per_sec: 0.1,
            addr_entries_threshold: 1000,
            peer_stale_secs: 3600,
        }
    }
}

/// Builds an `Args` instance pointing at the given NATS server
fn make_test_args(nats_port: u16, settings: AlertSettingsInTest) -> Args {
    Args {
        nats: nats_util::NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        ping_threshold: settings.ping_threshold,
        ping_window_secs: settings.ping_window_secs,
        addr_threshold: settings.addr_threshold,
        addr_window_secs: settings.addr_window_secs,
        addr_entries_initial_tokens: settings.addr_entries_initial_tokens,
        addr_entries_bucket_capacity: settings.addr_entries_bucket_capacity,
        addr_entries_rate_per_sec: settings.addr_entries_rate_per_sec,
        addr_entries_threshold: settings.addr_entries_threshold,
        log_level: log::Level::Trace,
        peer_stale_secs: settings.peer_stale_secs,
    }
}

/// Waits up to `d` for the next alert; panics if none arrives
async fn recv_alert(rx: &mut UnboundedReceiver<Alert>, d: Duration) -> Alert {
    timeout(d, rx.recv())
        .await
        .expect("timed out waiting for alert")
        .expect("alerter channel closed unexpectedly")
}

/// Returns true iff no alert arrives within `d`
async fn expect_no_alert(rx: &mut UnboundedReceiver<Alert>, d: Duration) -> bool {
    timeout(d, rx.recv()).await.is_err()
}

/// Destructures `Alert::Spammer` for assertions; panics on any other variant
fn unwrap_spammer(alert: Alert) -> (SpammerKind, u64, usize, usize) {
    match alert {
        Alert::Spammer {
            kind,
            peer_id,
            count,
            threshold,
            ..
        } => (kind, peer_id, count, threshold),
        other => panic!("expected Alert::Spammer, got {other:?}"),
    }
}

/// Publishes the same protobuf event `n` times on the given NATS subject
async fn publish_n(publisher: &NatsPublisherForTesting, subject: &str, event: &Event, n: usize) {
    let payload = event.encode_to_vec();
    for _ in 0..n {
        publisher
            .publish(subject.to_string(), payload.clone())
            .await;
    }
}

/// Constructs a protobuf `Event` wrapping a `Ping` message for the given peer
/// `inbound` controls whether the message appears as received from the peer
fn make_ping_event(peer_id: u64, addr: &str, inbound: bool) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "ping".to_string(),
                inbound,
                size: 8,
            },
            msg: Some(Msg::Ping(Ping { value: 42 })),
        })),
    }))
    .unwrap()
}

/// Constructs an inbound `Addr` message event carrying `entries` addresses
fn make_addr_event(peer_id: u64, addr: &str, entries: usize) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "addr".to_string(),
                inbound: true,
                size: 30,
            },
            msg: Some(Msg::Addr(Addr {
                addresses: vec![Address::default(); entries],
            })),
        })),
    }))
    .unwrap()
}

/// Constructs an inbound `AddrV2` message event carrying `entries` addresses
fn make_addrv2_event(peer_id: u64, addr: &str, entries: usize) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "addrv2".to_string(),
                inbound: true,
                size: 30,
            },
            msg: Some(Msg::Addrv2(AddrV2 {
                addresses: vec![Address::default(); entries],
            })),
        })),
    }))
    .unwrap()
}

/// Constructs an outbound `GETADDR` message event for the given peer
fn make_getaddr_event(peer_id: u64, addr: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "getaddr".to_string(),
                inbound: false,
                size: 0,
            },
            msg: Some(Msg::Getaddr(true)),
        })),
    }))
    .unwrap()
}

/// Destructures `Alert::AddrEntriesSpammer` for assertions; panics on any other variant
fn unwrap_addr_entries_spammer(alert: Alert) -> (u64, u64, u64, u64) {
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

/// Builds a ClosedConnection event for the given peer/addr
fn make_closed_event(peer_id: u64, addr: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(ConnectionEvent {
            event: Some(connection::connection_event::Event::Closed(
                ClosedConnection {
                    conn: Connection {
                        peer_id,
                        addr: addr.to_string(),
                        conn_type: 1,
                        network: 1,
                    },
                    time_established: 0,
                },
            )),
        })),
    }))
    .unwrap()
}

/// Boilerplate-collecting harness for integration tests.
/// Spins up a NATS server + publisher, an `IntegrationTestAlerter`, and the
/// `alerts::run` task. `shutdown` cleanly stops the task at the end of a test
struct TestHarness {
    publisher: NatsPublisherForTesting,
    rx: UnboundedReceiver<Alert>,
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    _server: NatsServerForTesting,
}

impl TestHarness {
    /// `mk_args` receives the NATS port and returns the `Args` to pass to `run`
    /// so each test can pin its own thresholds while reusing the harness setup
    async fn new(mk_args: impl FnOnce(u16) -> Args) -> Self {
        let server = NatsServerForTesting::new(&[]).await;
        let publisher = NatsPublisherForTesting::new(server.port).await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (alerter, rx) = IntegrationTestAlerter::new();
        let args = mk_args(server.port);
        let handle = tokio::spawn(alerts::run(args, alerter, shutdown_rx));
        sleep(Duration::from_secs(1)).await;
        Self {
            publisher,
            rx,
            shutdown_tx,
            handle,
            _server: server,
        }
    }

    async fn shutdown(self) {
        self.shutdown_tx.send(true).unwrap();
        self.handle.await.unwrap().unwrap();
    }
}

/// Verifies the PingSpammer threshold boundary: exactly `threshold` pings stay
/// silent; the (threshold + 1)-th ping fires the alert
#[tokio::test]
async fn test_ping_spammer() {
    let ping_threshold = 3;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_ping_event(1, "1.2.3.4:8333", true);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, ping_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold pings must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, count, threshold) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(peer_id, 1);
    assert_eq!(count, ping_threshold + 1);
    assert_eq!(threshold, ping_threshold);

    harness.shutdown().await;
}

/// Verifies the AddrSpammer threshold boundary with addr messages: exactly
/// `threshold` addrs stay silent; the (threshold + 1)-th fires the alert
#[tokio::test]
async fn test_addr_spammer() {
    let addr_threshold = 2;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_addr_event(2, "5.6.7.8:8333", 0);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, addr_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold addrs must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, count, threshold) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Addr);
    assert_eq!(peer_id, 2);
    assert_eq!(count, addr_threshold + 1);
    assert_eq!(threshold, addr_threshold);

    harness.shutdown().await;
}

/// Same boundary test as `test_addr_spammer` but with addrv2 messages,
/// verifying both message types share the same counter
#[tokio::test]
async fn test_addrv2_spammer() {
    let addr_threshold = 2;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_addrv2_event(3, "9.10.11.12:8333", 0);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, addr_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold addrv2 messages must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, count, threshold) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Addr);
    assert_eq!(peer_id, 3);
    assert_eq!(count, addr_threshold + 1);
    assert_eq!(threshold, addr_threshold);

    harness.shutdown().await;
}

/// Verifies that outbound pings are silently dropped and never trigger an alert
#[tokio::test]
async fn test_ping_spammer_outbound_ignored() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold: 3,
                ..Default::default()
            },
        )
    })
    .await;

    for _ in 0..4 {
        harness
            .publisher
            .publish(
                Subject::NetMsg.to_string(),
                make_ping_event(4, "99.99.99.99:8333", false).encode_to_vec(),
            )
            .await;
    }

    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "outbound pings must never produce alerts"
    );

    harness.shutdown().await;
}

/// Confirms that `run` returns a `NatsConnect` error when no NATS server is reachable
#[tokio::test]
async fn test_integration_alerts_fail_if_no_nats() {
    let (_, shutdown_rx) = watch::channel(false);
    let (alerter, _rx) = IntegrationTestAlerter::new();
    let alerts_handle = tokio::spawn(async move {
        let args = make_test_args(65535, AlertSettingsInTest::default());
        match alerts::run(args, alerter, shutdown_rx.clone()).await {
            Ok(_) => panic!("We should fail when no NATS server is reachable."),
            Err(e) => match e.downcast::<ConnectError>() {
                Ok(_) => (),
                Err(other_error) => panic!(
                    "Expected NatsConnect error since the NATS server isn't reachable but received error - {other_error:?}."
                ),
            },
        };
    });

    alerts_handle.await.unwrap();
}

/// Exercises the Close path for a non-spammer peer: cleanup happens silently
/// (no alert), confirming `log_disconnect` is guarded by `first_alerted`
#[tokio::test]
async fn test_closed_connection_cleans_state() {
    // threshold=10 so peer 99 never becomes a spammer
    let mut harness =
        TestHarness::new(|port| make_test_args(port, AlertSettingsInTest::default())).await;

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_ping_event(99, "1.1.1.1:8333", true).encode_to_vec(),
        )
        .await;

    sleep(Duration::from_millis(50)).await;

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(99, "1.1.1.1:8333").encode_to_vec(),
        )
        .await;

    // No alerts at all for this peer — neither spammer nor disconnect-of-flagged
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "non-spammer peer closing must not produce any alert"
    );

    harness.shutdown().await;
}

/// Verifies one-shot suppression: the alert fires when the threshold is
/// crossed and stays silent for any further hits on the same peer/kind
#[tokio::test]
async fn test_ping_spammer_fires_only_once() {
    let ping_threshold = 3;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_ping_event(10, "20.21.22.23:8333", true);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, ping_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold pings must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, _, _) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(peer_id, 10);

    // 6 more hits — none should re-alert
    publish_n(&harness.publisher, &subject, &event, 6).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "one-shot flag must suppress further PingSpammer alerts for the same peer"
    );

    harness.shutdown().await;
}

/// Verifies that a flagged peer's Close event emits a `PeerDisconnected`
/// alert through the `Alerter` channel as spam alerts
#[tokio::test]
async fn test_flagged_peer_disconnect_emits_disconnect_alert() {
    let ping_threshold = 3;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_ping_event(50, "50.51.52.53:8333", true);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, ping_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold pings must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, _, _) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(peer_id, 50);

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(50, "50.51.52.53:8333").encode_to_vec(),
        )
        .await;

    // Flagged peer's Close emits a `PeerDisconnected` alert through the same channel
    let disconnect = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    match disconnect {
        Alert::PeerDisconnected { peer_id, flags, .. } => {
            assert_eq!(peer_id, 50);
            assert_eq!(flags, vec![PeerFlag::PingSpammer]);
        }
        other => panic!("expected Alert::PeerDisconnected, got {other:?}"),
    }

    harness.shutdown().await;
}

/// Verifies that a peer which triggers every current peer heuristic reports all
/// reasons in canonical order when it disconnects
#[tokio::test]
async fn test_disconnect_includes_all_triggered_flags() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold: 1,
                addr_threshold: 0,
                addr_entries_initial_tokens: 1,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 0,
                ..Default::default()
            },
        )
    })
    .await;

    let peer_id = 51;
    let addr = "51.52.53.54:8333";
    publish_n(
        &harness.publisher,
        &Subject::NetMsg.to_string(),
        &make_ping_event(peer_id, addr, true),
        2,
    )
    .await;
    let (kind, alert_peer_id, _, _) =
        unwrap_spammer(recv_alert(&mut harness.rx, Duration::from_secs(2)).await);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(alert_peer_id, peer_id);

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addr_event(peer_id, addr, 3).encode_to_vec(),
        )
        .await;
    let (kind, alert_peer_id, _, _) =
        unwrap_spammer(recv_alert(&mut harness.rx, Duration::from_secs(2)).await);
    assert_eq!(kind, SpammerKind::Addr);
    assert_eq!(alert_peer_id, peer_id);
    let (alert_peer_id, _, _, _) =
        unwrap_addr_entries_spammer(recv_alert(&mut harness.rx, Duration::from_secs(2)).await);
    assert_eq!(alert_peer_id, peer_id);

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(peer_id, addr).encode_to_vec(),
        )
        .await;

    let disconnect = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    match disconnect {
        Alert::PeerDisconnected {
            peer_id: disconnected_peer_id,
            flags,
            ..
        } => {
            assert_eq!(disconnected_peer_id, peer_id);
            assert_eq!(
                flags,
                vec![
                    PeerFlag::PingSpammer,
                    PeerFlag::AddrSpammer,
                    PeerFlag::AddrEntriesSpammer,
                ]
            );
        }
        other => panic!("expected Alert::PeerDisconnected, got {other:?}"),
    }

    harness.shutdown().await;
}

/// Verifies that stale peers are evicted by the cleanup interval, and that
/// the eviction of a flagged peer emits a `PeerDisconnected` alert
#[tokio::test]
async fn test_stale_peer_cleanup_emits_disconnect_alert() {
    let ping_threshold = 3;
    // peer_stale_secs=1 so the cleanup tick evicts peer 60 quickly
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold,
                peer_stale_secs: 1,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_ping_event(60, "60.61.62.63:8333", true);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, ping_threshold).await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold pings must not fire an alert"
    );

    publish_n(&harness.publisher, &subject, &event, 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, _, _) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(peer_id, 60);

    // Wait for the cleanup interval to evict peer 60 (interval = peer_stale_secs = 1s)
    let disconnect = recv_alert(&mut harness.rx, Duration::from_secs(5)).await;
    match disconnect {
        Alert::PeerDisconnected { peer_id, flags, .. } => {
            assert_eq!(peer_id, 60);
            assert_eq!(flags, vec![PeerFlag::PingSpammer]);
        }
        other => panic!("expected Alert::PeerDisconnected, got {other:?}"),
    }

    harness.shutdown().await;
}

/// Verifies that a malformed (undecodable) NATS payload does not kill the
/// run loop: the tool must keep processing subsequent valid events
#[tokio::test]
async fn test_undecodable_payload_does_not_kill_tool() {
    let ping_threshold = 3;
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                ping_threshold,
                ..Default::default()
            },
        )
    })
    .await;

    // Garbage payload first — must be logged and skipped, not propagated
    harness
        .publisher
        .publish(Subject::NetMsg.to_string(), b"not a protobuf".to_vec())
        .await;

    sleep(Duration::from_millis(100)).await;

    // Then a valid spam burst — alert must still fire, proving the loop survived
    let event = make_ping_event(77, "7.7.7.7:8333", true);
    let subject = Subject::NetMsg.to_string();

    publish_n(&harness.publisher, &subject, &event, ping_threshold + 1).await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (kind, peer_id, _, _) = unwrap_spammer(alert);
    assert_eq!(kind, SpammerKind::Ping);
    assert_eq!(peer_id, 77);

    harness.shutdown().await;
}

/// With the defaults (seed 1, capacity 1000) a single oversized
/// addr message trips the limiter end-to-end: the bucket starts at 1, not at its
/// 1000 capacity, so 25 entries leave 24 rate-limited (> threshold 20)
#[tokio::test]
async fn test_addr_entries_single_message_core_seed() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                // keep the message-count threshold high so only the entry heuristic fires
                addr_threshold: 100,
                addr_entries_initial_tokens: 1,
                addr_entries_bucket_capacity: 1000,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 20,
                ..Default::default()
            },
        )
    })
    .await;

    // 25 entries against a seed-1 bucket: 1 processed, 24 rate-limited (> 20)
    let event = make_addr_event(82, "8.8.8.8:8333", 25);
    harness
        .publisher
        .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (peer_id, rate_limited, threshold, getaddr_requests_sent) =
        unwrap_addr_entries_spammer(alert);
    assert_eq!(peer_id, 82);
    assert_eq!(rate_limited, 24);
    assert_eq!(threshold, 20);
    assert_eq!(getaddr_requests_sent, 0);

    harness.shutdown().await;
}

/// addrv2 entries feed the same token bucket and can fire the alert on their own
#[tokio::test]
async fn test_addrv2_entries_spammer() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold: 100,
                addr_entries_initial_tokens: 5,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 5,
                ..Default::default()
            },
        )
    })
    .await;

    let event = make_addrv2_event(81, "8.8.4.4:8333", 20);
    harness
        .publisher
        .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (peer_id, _, threshold, getaddr_requests_sent) = unwrap_addr_entries_spammer(alert);
    assert_eq!(peer_id, 81);
    assert_eq!(threshold, 5);
    assert_eq!(getaddr_requests_sent, 0);

    harness.shutdown().await;
}

/// addr and addrv2 entries accumulate in one shared per-peer bucket
#[tokio::test]
async fn test_addr_and_addrv2_share_entries_bucket() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold: 100,
                addr_entries_initial_tokens: 10,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 5,
                ..Default::default()
            },
        )
    })
    .await;

    // First an addr with 8 entries: bucket 10 -> 2 left, nothing rate-limited
    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addr_event(83, "1.1.1.1:8333", 8).encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "8 entries against a 10-token bucket must not alert"
    );

    // Then an addrv2 with 8 entries: only 2 tokens remain, 6 rate-limited (> 5)
    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addrv2_event(83, "1.1.1.1:8333", 8).encode_to_vec(),
        )
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (peer_id, rate_limited, _, getaddr_requests_sent) = unwrap_addr_entries_spammer(alert);
    assert_eq!(peer_id, 83);
    assert_eq!(rate_limited, 6);
    assert_eq!(getaddr_requests_sent, 0);

    harness.shutdown().await;
}

/// Verifies that a peer flagged only via the entry token bucket (never the
/// ping/message-count heuristics) still emits a `PeerDisconnected` alert when
/// its conection closes, covering the `addr_entries.alerted_at` branch of
/// `disconnect_alert`
#[tokio::test]
async fn test_addr_entries_flagged_peer_disconnect_emits_disconnect_alert() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                // keep the message-count threshold high so only the entry heuristic fires
                addr_threshold: 100,
                addr_entries_initial_tokens: 5,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 5,
                ..Default::default()
            },
        )
    })
    .await;

    // 20 entries against a 5-token bucket: 15 rate-limited (> threshold 5) -> flag
    let event = make_addr_event(90, "9.9.9.9:8333", 20);
    harness
        .publisher
        .publish(Subject::NetMsg.to_string(), event.encode_to_vec())
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (peer_id, _, _, getaddr_requests_sent) = unwrap_addr_entries_spammer(alert);
    assert_eq!(peer_id, 90);
    assert_eq!(getaddr_requests_sent, 0);

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(90, "9.9.9.9:8333").encode_to_vec(),
        )
        .await;

    // The flagged peer's Close must emit a `PeerDisconnected` through the channel
    let disconnect = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    match disconnect {
        Alert::PeerDisconnected { peer_id, flags, .. } => {
            assert_eq!(peer_id, 90);
            assert_eq!(flags, vec![PeerFlag::AddrEntriesSpammer]);
        }
        other => panic!("expected Alert::PeerDisconnected, got {other:?}"),
    }

    harness.shutdown().await;
}

/// An outbound GETADDR grants a Core-style response allowance: a following
/// 1000-entry addr message is covered by the bucket and does not alert
#[tokio::test]
async fn test_addr_entries_getaddr_allows_response() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold: 100,
                addr_entries_initial_tokens: 1,
                addr_entries_bucket_capacity: 1000,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 20,
                ..Default::default()
            },
        )
    })
    .await;

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_getaddr_event(84, "8.8.8.8:8333").encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(200)).await,
        "outbound GETADDR must not alert"
    );

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addr_event(84, "8.8.8.8:8333", 1000).encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "1000-entry response to our GETADDR should be covered by the allowance"
    );

    harness.shutdown().await;
}

/// The GETADDR allowance only covers the expected response burst; entries beyond
/// the remaining bucket still become rate-limited and can trigger an alert
#[tokio::test]
async fn test_addr_entries_getaddr_response_excess_alerts() {
    let mut harness = TestHarness::new(|port| {
        make_test_args(
            port,
            AlertSettingsInTest {
                addr_threshold: 100,
                addr_entries_initial_tokens: 1,
                addr_entries_bucket_capacity: 1000,
                addr_entries_rate_per_sec: 0.0,
                addr_entries_threshold: 20,
                ..Default::default()
            },
        )
    })
    .await;

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_getaddr_event(85, "8.8.4.4:8333").encode_to_vec(),
        )
        .await;
    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addr_event(85, "8.8.4.4:8333", 1000).encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "the first 1000 entries should be covered by the GETADDR allowance"
    );

    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_addr_event(85, "8.8.4.4:8333", 30).encode_to_vec(),
        )
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    let (peer_id, rate_limited, threshold, getaddr_requests_sent) =
        unwrap_addr_entries_spammer(alert);
    assert_eq!(peer_id, 85);
    assert_eq!(rate_limited, 29);
    assert_eq!(threshold, 20);
    assert_eq!(getaddr_requests_sent, 1);

    harness.shutdown().await;
}
