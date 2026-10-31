#![cfg(feature = "nats_integration_tests")]

use alerts::{alerter::IntegrationTestAlerter, Alert, Args, SpammerKind};

use shared::{
    anyhow,
    async_nats::ConnectError,
    nats_subjects::Subject,
    prost::Message,
    protobuf::{
        bitcoin_primitives::{self, Address, InventoryItem},
        ebpf_extractor::{
            connection::{
                self, ClosedConnection, Connection, ConnectionEvent, EvictedInboundConnection,
                MisbehavingConnection,
            },
            ebpf,
            message::{
                self, message_event::Msg, Addr, AddrV2, Inv, Metadata, Ping, Unknown, Version,
            },
            validation::{self, BlockConnected, ValidationEvent},
            Ebpf,
        },
        event::{event::PeerObserverEvent, Event},
    },
    testing::{
        metrics_fetcher::{fetch_metrics_root, get_metric_value},
        nats_publisher::NatsPublisherForTesting,
        nats_server::NatsServerForTesting,
    },
    tokio::{
        self,
        sync::{mpsc::UnboundedReceiver, oneshot, watch},
        time::{sleep, timeout},
    },
};

use std::time::Duration;

struct AlertSettingsInTest {
    ping_threshold: usize,
    ping_window_secs: u64,
    addr_threshold: usize,
    addr_window_secs: u64,
    peer_stale_secs: u64,
}

impl Default for AlertSettingsInTest {
    fn default() -> Self {
        Self {
            ping_threshold: 10,
            ping_window_secs: 60,
            addr_threshold: 5,
            addr_window_secs: 60,
            peer_stale_secs: 3600,
        }
    }
}

/// Builds an `Args` instance pointing at the given NATS server
fn make_test_args(nats_port: u16, settings: AlertSettingsInTest) -> Args {
    let mut args = Args::for_tests(&format!("127.0.0.1:{}", nats_port));
    args.ping_spammer.ping_threshold = settings.ping_threshold;
    args.ping_spammer.ping_window_secs = settings.ping_window_secs;
    args.addr_spammer.addr_threshold = settings.addr_threshold;
    args.addr_spammer.addr_window_secs = settings.addr_window_secs;
    args.peer_stale_secs = settings.peer_stale_secs;
    args
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
/// `inbound` controls whether the message appears as received from the peer.
/// The nonce looks like one Bitcoin Core would draw, so only the ping count
/// matters to the heuristics
fn make_ping_event(peer_id: u64, addr: &str, inbound: bool) -> Event {
    make_ping_event_with_nonce(peer_id, addr, inbound, 0x0123_4567_89ab_cdef)
}

/// Like `make_ping_event`, with a chosen ping nonce
fn make_ping_event_with_nonce(peer_id: u64, addr: &str, inbound: bool, nonce: u64) -> Event {
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
            msg: Some(Msg::Ping(Ping { value: nonce })),
        })),
    }))
    .unwrap()
}

/// Constructs an inbound `Addr` message event for the given peer
fn make_addr_event(peer_id: u64, addr: &str) -> Event {
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
            msg: Some(Msg::Addr(Addr { addresses: vec![] })),
        })),
    }))
    .unwrap()
}

/// Constructs an inbound `AddrV2` message event for the given peer
fn make_addrv2_event(peer_id: u64, addr: &str) -> Event {
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
            msg: Some(Msg::Addrv2(AddrV2 { addresses: vec![] })),
        })),
    }))
    .unwrap()
}

/// Builds a ClosedConnection event for the given peer/addr. The time the
/// connection was established is left unknown
fn make_closed_event(peer_id: u64, addr: &str) -> Event {
    make_closed_event_established_at(peer_id, addr, 0)
}

/// Builds a ClosedConnection event for an inbound connection established at
/// the UNIX timestamp `time_established`
fn make_closed_event_established_at(peer_id: u64, addr: &str, time_established: u64) -> Event {
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
                    time_established,
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
    metrics_port: u16,
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
        let (addr_tx, addr_rx) = oneshot::channel();
        let handle = tokio::spawn(alerts::run(args, alerter, shutdown_rx, Some(addr_tx)));
        let metrics_port = addr_rx
            .await
            .expect("alerts tool should send its metrics address")
            .port();
        sleep(Duration::from_secs(1)).await;
        Self {
            publisher,
            metrics_port,
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

    let event = make_addr_event(2, "5.6.7.8:8333");
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

    let event = make_addrv2_event(3, "9.10.11.12:8333");
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
        match alerts::run(args, alerter, shutdown_rx.clone(), None).await {
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
        Alert::PeerDisconnected { peer_id, .. } => assert_eq!(peer_id, 50),
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
        Alert::PeerDisconnected { peer_id, .. } => assert_eq!(peer_id, 60),
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

/// Builds a MisbehavingConnection event for the given peer
fn make_misbehaving_event(peer_id: u64, reason: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(ConnectionEvent {
            event: Some(connection::connection_event::Event::Misbehaving(
                MisbehavingConnection {
                    id: peer_id,
                    message: reason.to_string(),
                },
            )),
        })),
    }))
    .unwrap()
}

/// Verifies that a misbehaving report from Bitcoin Core becomes an alert with
/// the peer's address and reason, and that the usual disconnect afterwards
/// stays silent because nothing else flagged the peer
#[tokio::test]
async fn test_misbehaving_peer() {
    let mut harness =
        TestHarness::new(|port| make_test_args(port, AlertSettingsInTest::default())).await;

    // One message from the peer so the tool knows its address
    harness
        .publisher
        .publish(
            Subject::NetMsg.to_string(),
            make_ping_event(31, "31.31.31.31:8333", true).encode_to_vec(),
        )
        .await;
    // The two subjects are separate NATS subscriptions, so give the ping a
    // moment to arrive before the report on the other subject
    sleep(Duration::from_millis(50)).await;
    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_misbehaving_event(31, "headers message size = 2001").encode_to_vec(),
        )
        .await;

    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::MisbehavingPeer {
            peer_id: 31,
            addr: "31.31.31.31:8333".to_string(),
            reason: "headers message size = 2001".to_string(),
        }
    );

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(31, "31.31.31.31:8333").encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "a misbehaving peer disconnecting must not produce a PeerDisconnected alert"
    );

    // A peer we never heard from is reported with an unknown address
    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_misbehaving_event(32, "invalid header received").encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::MisbehavingPeer {
            peer_id: 32,
            addr: "unknown".to_string(),
            reason: "invalid header received".to_string(),
        }
    );

    harness.shutdown().await;
}

/// Builds an inbound handshake message event. `command` is one of the
/// messages with no payload: verack, wtxidrelay, or sendaddrv2
fn make_handshake_event(peer_id: u64, addr: &str, command: &str) -> Event {
    let msg = match command {
        "verack" => Msg::Verack(true),
        "wtxidrelay" => Msg::Wtxidrelay(true),
        "sendaddrv2" => Msg::Sendaddrv2(true),
        other => panic!("no builder for handshake message {other}"),
    };
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: command.to_string(),
                inbound: true,
                size: 0,
            },
            msg: Some(msg),
        })),
    }))
    .unwrap()
}

/// Verifies that a handshake message after the peer's verack fires one
/// HandshakeAfterVerack alert, that the same messages before verack are fine,
/// and that the flagged peer's disconnect is reported
#[tokio::test]
async fn test_handshake_after_verack() {
    let mut harness =
        TestHarness::new(|port| make_test_args(port, AlertSettingsInTest::default())).await;
    let subject = Subject::NetMsg.to_string();
    let addr = "41.41.41.41:8333";

    for command in ["wtxidrelay", "sendaddrv2", "verack"] {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_handshake_event(41, addr, command).encode_to_vec(),
            )
            .await;
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "a normal handshake must not alert"
    );

    for command in ["sendaddrv2", "verack"] {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_handshake_event(41, addr, command).encode_to_vec(),
            )
            .await;
    }
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::HandshakeAfterVerack {
            peer_id: 41,
            addr: addr.to_string(),
            command: "sendaddrv2".to_string(),
        }
    );
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "the peer is only reported once"
    );

    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(41, addr).encode_to_vec(),
        )
        .await;
    match recv_alert(&mut harness.rx, Duration::from_secs(2)).await {
        Alert::PeerDisconnected { peer_id, .. } => assert_eq!(peer_id, 41),
        other => panic!("expected Alert::PeerDisconnected, got {other:?}"),
    }

    harness.shutdown().await;
}

/// Verifies that pings with a nonce below 2^32 are counted per peer and fire
/// one SmallPingNonce alert above the threshold, while pings with full-size
/// nonces do not count
#[tokio::test]
async fn test_small_ping_nonce() {
    let threshold = 2;
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        // Keep the ping spammer quiet so only the nonce check speaks up
        args.ping_spammer.ping_threshold = 100;
        args.small_ping_nonce.small_ping_nonce_threshold = threshold;
        args
    })
    .await;
    let subject = Subject::NetMsg.to_string();
    let addr = "51.51.51.51:8333";

    // Full-size nonces, then exactly threshold small ones: silence
    publish_n(
        &harness.publisher,
        &subject,
        &make_ping_event(51, addr, true),
        5,
    )
    .await;
    for nonce in [0, 1] {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_ping_event_with_nonce(51, addr, true, nonce).encode_to_vec(),
            )
            .await;
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold small nonces must not alert"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_ping_event_with_nonce(51, addr, true, u32::MAX as u64).encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::SmallPingNonce {
            peer_id: 51,
            addr: addr.to_string(),
            count: threshold + 1,
            threshold,
        }
    );

    harness.shutdown().await;
}

/// Builds an inbound `version` message event with the given relay flag and a
/// sender clock that agrees with ours
fn make_version_event(peer_id: u64, addr: &str, relay: bool) -> Event {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    make_version_event_at(peer_id, addr, relay, now)
}

/// Builds an inbound `version` message event carrying `timestamp` as the
/// sender's time
fn make_version_event_at(peer_id: u64, addr: &str, relay: bool, timestamp: i64) -> Event {
    let address = || Address {
        timestamp: 0,
        services: 1,
        port: 8333,
        address: Some(bitcoin_primitives::address::Address::Ipv4(
            "127.0.0.1".to_string(),
        )),
    };
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "version".to_string(),
                inbound: true,
                size: 100,
            },
            msg: Some(Msg::Version(Version {
                version: 70016,
                services: 1,
                timestamp,
                receiver: address(),
                sender: address(),
                nonce: 1,
                user_agent: "/test/".to_string(),
                start_height: 0,
                relay,
            })),
        })),
    }))
    .unwrap()
}

/// Builds an inbound `inv` message event announcing one transaction
fn make_tx_inv_event(peer_id: u64, addr: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: "inv".to_string(),
                inbound: true,
                size: 37,
            },
            msg: Some(Msg::Inv(Inv {
                items: vec![InventoryItem {
                    item: Some(bitcoin_primitives::inventory_item::Item::Wtx(vec![7; 32])),
                }],
            })),
        })),
    }))
    .unwrap()
}

/// Verifies that a peer announcing a transaction after setting relay=false in
/// its version message is reported once, and a peer with relay=true is not
#[tokio::test]
async fn test_tx_relay_mismatch() {
    let mut harness =
        TestHarness::new(|port| make_test_args(port, AlertSettingsInTest::default())).await;
    let subject = Subject::NetMsg.to_string();

    harness
        .publisher
        .publish(
            subject.clone(),
            make_version_event(61, "61.61.61.61:8333", true).encode_to_vec(),
        )
        .await;
    harness
        .publisher
        .publish(
            subject.clone(),
            make_tx_inv_event(61, "61.61.61.61:8333").encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "a peer with relay=true may announce transactions"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_version_event(62, "62.62.62.62:8333", false).encode_to_vec(),
        )
        .await;
    publish_n(
        &harness.publisher,
        &subject,
        &make_tx_inv_event(62, "62.62.62.62:8333"),
        3,
    )
    .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::TxRelayMismatch {
            peer_id: 62,
            addr: "62.62.62.62:8333".to_string(),
            command: "inv".to_string(),
        }
    );
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "the peer is only reported once"
    );

    harness.shutdown().await;
}

/// Builds a BlockConnected validation event
fn make_block_connected_event(height: i32, connection_time_ns: u64) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Validation(ValidationEvent {
            event: Some(validation::validation_event::Event::BlockConnected(
                BlockConnected {
                    hash: vec![0xab; 32],
                    height,
                    transactions: 2000,
                    inputs: 5000,
                    sigops: 8000,
                    connection_time: connection_time_ns,
                },
            )),
        })),
    }))
    .unwrap()
}

/// Verifies that only blocks taking longer than --slow-block-secs to connect
/// are reported, with the block details
#[tokio::test]
async fn test_slow_block() {
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        args.slow_block.slow_block_secs = 1;
        args
    })
    .await;
    let subject = Subject::Validation.to_string();

    harness
        .publisher
        .publish(
            subject.clone(),
            make_block_connected_event(800_000, 500_000_000).encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "a block connected in half a second is fine"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_block_connected_event(800_001, 2_500_000_000).encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::SlowBlock {
            height: 800_001,
            hash: "abababababababababababababababababababababababababababababababab".to_string(),
            connection_time_ms: 2500,
            threshold_secs: 1,
            transactions: 2000,
            inputs: 5000,
            sigops: 8000,
        }
    );

    harness.shutdown().await;
}

/// Verifies that a tip without blocks for --stale-tip-secs is reported once,
/// and that the next block is reported as recovery
#[tokio::test]
async fn test_stale_tip() {
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        args.stale_tip.stale_tip_secs = 1;
        args
    })
    .await;

    // No block since the tool started
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(5)).await;
    match alert {
        Alert::StaleTip {
            since_secs,
            threshold_secs,
            last_height,
        } => {
            assert!(since_secs >= 1);
            assert_eq!(threshold_secs, 1);
            assert_eq!(last_height, None);
        }
        other => panic!("expected Alert::StaleTip, got {other:?}"),
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(1500)).await,
        "a stale tip is reported once"
    );

    harness
        .publisher
        .publish(
            Subject::Validation.to_string(),
            make_block_connected_event(800_002, 1_000_000).encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    match alert {
        Alert::TipRecovered { height, stale_secs } => {
            assert_eq!(height, 800_002);
            assert!(stale_secs >= 2);
        }
        other => panic!("expected Alert::TipRecovered, got {other:?}"),
    }

    harness.shutdown().await;
}

/// Builds an EvictedInboundConnection event for the given peer/addr
fn make_evicted_event(peer_id: u64, addr: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Connection(ConnectionEvent {
            event: Some(connection::connection_event::Event::InboundEvicted(
                EvictedInboundConnection {
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

/// Verifies that closing more than --inbound-drop-threshold inbound connections
/// in the window fires one InboundConnectionDrops alert, and that evicted
/// connections are not counted
#[tokio::test]
async fn test_inbound_connection_drops() {
    let threshold = 2;
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        args.inbound_connection_drops.inbound_drop_threshold = threshold;
        args
    })
    .await;
    let subject = Subject::NetConn.to_string();
    // All connections were up for two minutes
    let established = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120;

    // An evicted connection closes afterwards, but must not count
    harness
        .publisher
        .publish(
            subject.clone(),
            make_evicted_event(70, "70.0.0.1:8333").encode_to_vec(),
        )
        .await;
    harness
        .publisher
        .publish(
            subject.clone(),
            make_closed_event_established_at(70, "70.0.0.1:8333", established).encode_to_vec(),
        )
        .await;
    for peer_id in 71..=72 {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_closed_event_established_at(
                    peer_id,
                    &format!("70.0.0.{peer_id}:8333"),
                    established,
                )
                .encode_to_vec(),
            )
            .await;
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold drops must not alert"
    );

    for peer_id in 73..=75 {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_closed_event_established_at(
                    peer_id,
                    &format!("70.0.0.{peer_id}:8333"),
                    established,
                )
                .encode_to_vec(),
            )
            .await;
    }
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::InboundConnectionDrops {
            count: threshold + 1,
            window_secs: 300,
            threshold,
            min_age_secs: 60,
        }
    );
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "further drops in the same episode must not alert again"
    );

    harness.shutdown().await;
}

/// Verifies that closing more than --old-connection-drop-threshold connections
/// older than --old-connection-age-secs fires one OldConnectionDrops alert, and
/// that young connections and connections of unknown age are not counted
#[tokio::test]
async fn test_old_connection_drops() {
    let threshold = 2;
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        args.old_connection_drops.old_connection_drop_threshold = threshold;
        args.old_connection_drops.old_connection_age_secs = 3600;
        args
    })
    .await;
    let subject = Subject::NetConn.to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // A young connection, one of unknown age, and exactly threshold old ones
    harness
        .publisher
        .publish(
            subject.clone(),
            make_closed_event_established_at(80, "80.0.0.80:8333", now - 60).encode_to_vec(),
        )
        .await;
    harness
        .publisher
        .publish(
            subject.clone(),
            make_closed_event(81, "80.0.0.81:8333").encode_to_vec(),
        )
        .await;
    for peer_id in 82..=83 {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_closed_event_established_at(
                    peer_id,
                    &format!("80.0.0.{peer_id}:8333"),
                    now - 7200,
                )
                .encode_to_vec(),
            )
            .await;
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "young, unknown-age, and exactly threshold old drops must not alert"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_closed_event_established_at(84, "80.0.0.84:8333", now - 7200).encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::OldConnectionDrops {
            count: threshold + 1,
            window_secs: 300,
            threshold,
            min_age_secs: 3600,
        }
    );

    harness.shutdown().await;
}

/// Verifies that fired alerts are counted on the metrics endpoint by kind and
/// that kinds that never fired are present with a count of zero
#[tokio::test]
async fn test_alert_metrics() {
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

    let event = make_ping_event(90, "90.90.90.90:8333", true);
    publish_n(
        &harness.publisher,
        &Subject::NetMsg.to_string(),
        &event,
        ping_threshold + 1,
    )
    .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert!(matches!(alert, Alert::Spammer { .. }));

    let metrics_raw = fetch_metrics_root(harness.metrics_port).expect("Could not fetch metrics");
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_total",
            "alert",
            "ping_spammer"
        ),
        1
    );
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_total",
            "alert",
            "addr_spammer"
        ),
        0
    );
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_total",
            "alert",
            "stale_tip"
        ),
        0
    );
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_flagged_peers",
            "alert",
            "ping_spammer"
        ),
        1
    );
    assert!(
        metrics_raw.contains(
            "peerobserver_alerts_flagged_peer_info{addr=\"90.90.90.90:8333\",alert=\"ping_spammer\",peer_id=\"90\"} 1"
        ),
        "the flagged peer has an info series"
    );
    assert!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_last_fired_timestamp",
            "alert",
            "ping_spammer"
        ) > 0
    );
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_last_fired_timestamp",
            "alert",
            "stale_tip"
        ),
        0
    );

    // Once the peer leaves, it is no longer flagged
    harness
        .publisher
        .publish(
            Subject::NetConn.to_string(),
            make_closed_event(90, "90.90.90.90:8333").encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert!(matches!(alert, Alert::PeerDisconnected { .. }));
    let metrics_raw = fetch_metrics_root(harness.metrics_port).expect("Could not fetch metrics");
    assert_eq!(
        get_metric_value(
            &metrics_raw,
            "peerobserver_alerts_flagged_peers",
            "alert",
            "ping_spammer"
        ),
        0
    );
    assert!(
        !metrics_raw.contains("peer_id=\"90\""),
        "the info series is removed when the peer leaves"
    );

    harness.shutdown().await;
}

/// Builds an inbound message event with a command rust-bitcoin does not know
fn make_unknown_event(peer_id: u64, addr: &str, command: &str) -> Event {
    Event::new(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(ebpf::EbpfEvent::Message(message::MessageEvent {
            meta: Metadata {
                peer_id,
                addr: addr.to_string(),
                conn_type: 1,
                command: command.to_string(),
                inbound: true,
                size: 0,
            },
            msg: Some(Msg::Unknown(Unknown {
                command: command.to_string(),
                payload: vec![1, 2, 3],
            })),
        })),
    }))
    .unwrap()
}

/// Verifies that more than --unknown-message-threshold unknown messages from
/// one peer fire one UnknownMessages alert naming the last command
#[tokio::test]
async fn test_unknown_messages() {
    let threshold = 2;
    let mut harness = TestHarness::new(|port| {
        let mut args = make_test_args(port, AlertSettingsInTest::default());
        args.unknown_messages.unknown_message_threshold = threshold;
        args
    })
    .await;
    let subject = Subject::NetMsg.to_string();
    let addr = "100.0.0.1:8333";

    for command in ["foo", "bar"] {
        harness
            .publisher
            .publish(
                subject.clone(),
                make_unknown_event(100, addr, command).encode_to_vec(),
            )
            .await;
    }
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "exactly threshold unknown messages must not alert"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_unknown_event(100, addr, "baz").encode_to_vec(),
        )
        .await;
    let alert = recv_alert(&mut harness.rx, Duration::from_secs(2)).await;
    assert_eq!(
        alert,
        Alert::UnknownMessages {
            peer_id: 100,
            addr: addr.to_string(),
            count: threshold + 1,
            threshold,
            last_command: "baz".to_string(),
        }
    );

    harness.shutdown().await;
}

/// Verifies that a version message with a time more than
/// --version-time-offset-secs off fires a VersionTimeOffset alert, and one
/// with a close time does not
#[tokio::test]
async fn test_version_time_offset() {
    let mut harness =
        TestHarness::new(|port| make_test_args(port, AlertSettingsInTest::default())).await;
    let subject = Subject::NetMsg.to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    harness
        .publisher
        .publish(
            subject.clone(),
            make_version_event_at(110, "110.0.0.1:8333", true, now - 60).encode_to_vec(),
        )
        .await;
    assert!(
        expect_no_alert(&mut harness.rx, Duration::from_millis(500)).await,
        "a minute of clock difference is fine"
    );

    harness
        .publisher
        .publish(
            subject.clone(),
            make_version_event_at(111, "110.0.0.2:8333", true, now - 3600).encode_to_vec(),
        )
        .await;
    match recv_alert(&mut harness.rx, Duration::from_secs(2)).await {
        Alert::VersionTimeOffset {
            peer_id,
            addr,
            offset_secs,
            threshold_secs,
            user_agent,
        } => {
            assert_eq!(peer_id, 111);
            assert_eq!(addr, "110.0.0.2:8333");
            assert!(
                (-3605..=-3595).contains(&offset_secs),
                "offset was {offset_secs}"
            );
            assert_eq!(threshold_secs, 600);
            assert_eq!(user_agent, "/test/");
        }
        other => panic!("expected Alert::VersionTimeOffset, got {other:?}"),
    }

    harness.shutdown().await;
}
