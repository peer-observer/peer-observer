#![cfg(feature = "nats_integration_tests")]
#![cfg(feature = "node_integration_tests")]

mod common;

use common::{
    EnabledRPCsInTest, QUERY_INTERVAL_SECONDS, make_test_args, setup, setup_two_connected_nodes,
};

use shared::{
    testing::{
        metrics_fetcher::{fetch_metrics, get_metric_value},
        nats_server::NatsServerForTesting,
    },
    tokio::{
        self,
        sync::{oneshot, watch},
    },
};

/// Verifies the Prometheus metrics server starts and responds to HTTP requests.
#[tokio::test]
async fn test_integration_metrics_server_basic() {
    setup();
    let (node1, _node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr_tx, addr_rx) = oneshot::channel();

    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            node1.rpc_url().replace("http://", ""),
            node1.params.cookie_file.display().to_string(),
            "127.0.0.1:0".to_string(),
            EnabledRPCsInTest {
                ..Default::default()
            },
        );
        let _ = rpc_extractor::run(args, shutdown_rx.clone(), Some(addr_tx)).await;
    });

    let metrics_addr = addr_rx.await.expect("Should receive bound address");
    let metrics_port = metrics_addr.port();

    // Fetch metrics and verify the server responds
    let metrics = fetch_metrics(metrics_port, "/metrics");
    assert!(
        metrics.is_ok(),
        "Metrics server should respond: {:?}",
        metrics
    );

    // With per-instance registries, metrics only appear after being accessed.
    // This basic test verifies the server starts and responds.
    // Actual metric content is verified by other tests that make RPC calls.

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();
}

/// Verifies that a successful RPC call records its duration in the histogram.
#[tokio::test]
async fn test_integration_metrics_rpc_fetch_duration() {
    setup();
    let (node1, _node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr_tx, addr_rx) = oneshot::channel();

    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            node1.rpc_url().replace("http://", ""),
            node1.params.cookie_file.display().to_string(),
            "127.0.0.1:0".to_string(),
            EnabledRPCsInTest {
                uptime: true, // lightweight RPC
                ..Default::default()
            },
        );
        let _ = rpc_extractor::run(args, shutdown_rx.clone(), Some(addr_tx)).await;
    });

    let metrics_addr = addr_rx.await.expect("Should receive bound address");
    let metrics_port = metrics_addr.port();

    // Wait for at least one RPC query cycle
    tokio::time::sleep(tokio::time::Duration::from_secs(QUERY_INTERVAL_SECONDS + 1)).await;

    // Fetch metrics and verify duration was recorded
    let metrics = fetch_metrics(metrics_port, "/metrics").expect("Should fetch metrics");

    // Check that the histogram count for uptime is at least 1
    let uptime_count = get_metric_value(
        &metrics,
        "rpcextractor_rpc_fetch_duration_seconds_count",
        "rpc_method",
        "uptime",
    );
    assert!(
        uptime_count >= 1,
        "Should have recorded at least one uptime RPC call, got: {}",
        uptime_count
    );

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();
}

/// Verifies that every enabled RPC method records its duration after one query cycle.
#[tokio::test]
async fn test_integration_metrics_all_rpc_methods_duration() {
    setup();
    let (node1, _node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr_tx, addr_rx) = oneshot::channel();
    let rpcs = EnabledRPCsInTest::all();

    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            node1.rpc_url().replace("http://", ""),
            node1.params.cookie_file.display().to_string(),
            "127.0.0.1:0".to_string(),
            EnabledRPCsInTest::all(),
        );
        let _ = rpc_extractor::run(args, shutdown_rx.clone(), Some(addr_tx)).await;
    });

    let metrics_addr = addr_rx.await.expect("Should receive bound address");
    let metrics_port = metrics_addr.port();

    // Wait for at least one RPC query cycle
    tokio::time::sleep(tokio::time::Duration::from_secs(QUERY_INTERVAL_SECONDS + 1)).await;

    // Fetch metrics
    let metrics = fetch_metrics(metrics_port, "/metrics").expect("Should fetch metrics");

    // Verify that each enabled RPC method has recorded at least one call
    for method in rpcs.enabled_methods() {
        let count = get_metric_value(
            &metrics,
            "rpcextractor_rpc_fetch_duration_seconds_count",
            "rpc_method",
            method,
        );
        assert!(
            count >= 1,
            "Should have recorded at least one {} RPC call, got: {}",
            method,
            count
        );
    }

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();
}

/// Verifies that a failing RPC call increments the error counter and doesnt record duration (stop_and_discard).
#[tokio::test]
async fn test_integration_metrics_rpc_fetch_errors() {
    setup();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr_tx, addr_rx) = oneshot::channel();

    // Create a temporary cookie file (required by Args validation)
    let temp_dir = std::env::temp_dir();
    let cookie_file = temp_dir.join("test_cookie_rpc_fetch_errors");
    std::fs::write(&cookie_file, "__cookie__:test").expect("Failed to write cookie file");

    let cookie_file_path = cookie_file.display().to_string();
    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            "127.0.0.1:1".to_string(), // Unreachable RPC host
            cookie_file_path,
            "127.0.0.1:0".to_string(),
            EnabledRPCsInTest {
                uptime: true, // will fail
                ..Default::default()
            },
        );
        let _ = rpc_extractor::run(args, shutdown_rx.clone(), Some(addr_tx)).await;
    });

    let metrics_addr = addr_rx.await.expect("Should receive bound address");
    let metrics_port = metrics_addr.port();

    // Wait for at least one RPC query cycle (which will fail)
    tokio::time::sleep(tokio::time::Duration::from_secs(QUERY_INTERVAL_SECONDS + 1)).await;

    // Fetch metrics and verify error counter was incremented
    let metrics = fetch_metrics(metrics_port, "/metrics").expect("Should fetch metrics");

    // Check that the error counter for uptime is at least 1
    let error_count = get_metric_value(
        &metrics,
        "rpcextractor_rpc_fetch_errors_total",
        "rpc_method",
        "uptime",
    );
    assert!(
        error_count >= 1,
        "Should have recorded at least one uptime RPC error, got: {}. Metrics:\n{}",
        error_count,
        metrics
    );

    // Verify that the duration histogram was NOT incremented on error (stop_and_discard)
    let duration_count = get_metric_value(
        &metrics,
        "rpcextractor_rpc_fetch_duration_seconds_count",
        "rpc_method",
        "uptime",
    );
    assert_eq!(
        duration_count, 0,
        "Duration histogram should NOT be incremented on error (stop_and_discard), got: {}",
        duration_count
    );

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();

    // Cleanup
    let _ = std::fs::remove_file(&cookie_file);
}

/// Verifies that an auth failure increments the error counter and does not record duration.
#[tokio::test]
async fn test_integration_metrics_rpc_fetch_errors_invalid_auth() {
    setup();
    let (node1, _node2) = setup_two_connected_nodes();
    let nats_server = NatsServerForTesting::new(&[]).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (addr_tx, addr_rx) = oneshot::channel();

    // Create a cookie file with invalid credentials
    let temp_dir = std::env::temp_dir();
    let invalid_cookie_file = temp_dir.join("invalid_cookie_rpc_fetch_errors_invalid_auth");
    std::fs::write(&invalid_cookie_file, "__cookie__:invalid_password")
        .expect("Failed to write invalid cookie file");

    let invalid_cookie_path = invalid_cookie_file.display().to_string();
    let rpc_url = node1.rpc_url().replace("http://", "");
    let rpc_extractor_handle = tokio::spawn(async move {
        let args = make_test_args(
            nats_server.port,
            rpc_url,
            invalid_cookie_path,
            "127.0.0.1:0".to_string(),
            EnabledRPCsInTest {
                uptime: true, // will fail due to auth
                ..Default::default()
            },
        );
        let _ = rpc_extractor::run(args, shutdown_rx.clone(), Some(addr_tx)).await;
    });

    let metrics_addr = addr_rx.await.expect("Should receive bound address");
    let metrics_port = metrics_addr.port();

    // Wait for at least one RPC query cycle (which will fail due to invalid auth)
    tokio::time::sleep(tokio::time::Duration::from_secs(QUERY_INTERVAL_SECONDS + 1)).await;

    // Fetch metrics and verify error counter was incremented
    let metrics = fetch_metrics(metrics_port, "/metrics").expect("Should fetch metrics");

    // Check that the error counter for uptime is at least 1
    let error_count = get_metric_value(
        &metrics,
        "rpcextractor_rpc_fetch_errors_total",
        "rpc_method",
        "uptime",
    );
    assert!(
        error_count >= 1,
        "Should have recorded at least one uptime RPC error due to invalid auth, got: {}. Metrics:\n{}",
        error_count,
        metrics
    );

    // Verify that the duration histogram was NOT incremented on error (stop_and_discard)
    let duration_count = get_metric_value(
        &metrics,
        "rpcextractor_rpc_fetch_duration_seconds_count",
        "rpc_method",
        "uptime",
    );
    assert_eq!(
        duration_count, 0,
        "Duration histogram should NOT be incremented on error (stop_and_discard), got: {}",
        duration_count
    );

    shutdown_tx.send(true).unwrap();
    rpc_extractor_handle.await.unwrap();

    // Cleanup
    let _ = std::fs::remove_file(&invalid_cookie_file);
}
