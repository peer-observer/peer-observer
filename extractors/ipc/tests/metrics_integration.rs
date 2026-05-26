#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

mod common;

use common::{QUERY_INTERVAL_SECONDS, configure_node, ipc_socket_path, make_test_args, setup};

use shared::{
    testing::{
        metrics_fetcher::{fetch_metrics, get_metric_value},
        nats_server::NatsServerForTesting,
    },
    tokio::{
        self, select,
        sync::{oneshot, watch},
        task::LocalSet,
        time::{Duration, sleep},
    },
};

/// Verifies the Prometheus metrics server starts and responds to HTTP requests.
#[tokio::test]
async fn test_integration_metrics_server_basic() {
    setup();
    let node = configure_node();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let args = make_test_args(nats_server.port, ipc_socket_path(&node));

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (addr_tx, addr_rx) = oneshot::channel();

            let mut handle = tokio::task::spawn_local(async move {
                ipc_extractor::run(args, shutdown_rx, Some(addr_tx))
                    .await
                    .expect("ipc extractor failed");
            });

            let metrics_port = select! {
                addr = addr_rx => addr.expect("ipc-extractor should send bound address").port(),
                result = &mut handle => {
                    result.unwrap();
                    unreachable!("ipc-extractor task exited before sending bound address");
                }
            };

            let metrics = fetch_metrics(metrics_port, "/metrics");
            assert!(
                metrics.is_ok(),
                "Metrics server should respond: {:?}",
                metrics
            );

            shutdown_tx.send(true).unwrap();
            handle.await.unwrap();
        })
        .await;
}

/// Verifies that a successful IPC call records its duration in the histogram.
#[tokio::test]
async fn test_integration_metrics_ipc_fetch_duration() {
    setup();
    let node = configure_node();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let args = make_test_args(nats_server.port, ipc_socket_path(&node));

    let local = LocalSet::new();
    local
        .run_until(async move {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let (addr_tx, addr_rx) = oneshot::channel();

            let mut handle = tokio::task::spawn_local(async move {
                ipc_extractor::run(args, shutdown_rx, Some(addr_tx))
                    .await
                    .expect("ipc extractor failed");
            });

            let metrics_port = select! {
                addr = addr_rx => addr.expect("ipc-extractor should send bound address").port(),
                result = &mut handle => {
                    result.unwrap();
                    unreachable!("ipc-extractor task exited before sending bound address");
                }
            };

            // Wait for at least one query cycle.
            sleep(Duration::from_secs(QUERY_INTERVAL_SECONDS + 1)).await;

            let metrics = fetch_metrics(metrics_port, "/metrics").expect("Should fetch metrics");

            let count = get_metric_value(
                &metrics,
                "ipcextractor_ipc_fetch_duration_seconds_count",
                "ipc_method",
                "get_tip",
            );
            assert!(
                count >= 1,
                "Should have recorded at least one get_tip call, got: {}",
                count
            );

            shutdown_tx.send(true).unwrap();
            handle.await.unwrap();
        })
        .await;
}
