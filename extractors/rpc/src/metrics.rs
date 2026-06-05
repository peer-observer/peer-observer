use shared::anyhow::{Context, Result};
use shared::prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
};

const NAMESPACE: &str = "rpcextractor";

pub const LABEL_RPC_METHOD: &str = "rpc_method";

const RPC_DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Metrics for the rpc-extractor.
/// Each instance has its own registry, allowing for parallel testing.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: Registry,
    /// Time it took to fetch data from the RPC endpoint.
    pub rpc_fetch_duration: HistogramVec,
    /// Number of errors while fetching data from the RPC endpoint.
    pub rpc_fetch_errors: IntCounterVec,
    /// Number of errors while converting an RPC response into its model type.
    pub rpc_model_errors: IntCounterVec,
    /// Number of errors while publishing events to NATS.
    pub nats_publish_errors: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new_custom(Some(NAMESPACE.to_string()), None)
            .context("Could not create prometheus registry")?;

        let rpc_fetch_duration = register_histogram_vec_with_registry!(
            HistogramOpts::new(
                "rpc_fetch_duration_seconds",
                "Time it took to fetch data from the RPC endpoint."
            )
            .buckets(RPC_DURATION_BUCKETS.to_vec()),
            &[LABEL_RPC_METHOD],
            registry
        )
        .context("Could not create rpc_fetch_duration_seconds metric")?;

        let rpc_fetch_errors = register_int_counter_vec_with_registry!(
            Opts::new(
                "rpc_fetch_errors_total",
                "Number of errors while fetching data from the RPC endpoint."
            ),
            &[LABEL_RPC_METHOD],
            registry
        )
        .context("Could not create rpc_fetch_errors_total metric")?;

        let rpc_model_errors = register_int_counter_vec_with_registry!(
            Opts::new(
                "rpc_model_errors_total",
                "Number of errors while converting an RPC response into its model type."
            ),
            &[LABEL_RPC_METHOD],
            registry
        )
        .context("Could not create rpc_model_errors_total metric")?;

        let nats_publish_errors = register_int_counter_vec_with_registry!(
            Opts::new(
                "nats_publish_errors_total",
                "Number of errors while publishing events to NATS."
            ),
            &[LABEL_RPC_METHOD],
            registry
        )
        .context("Could not create nats_publish_errors_total metric")?;

        Ok(Self {
            registry,
            rpc_fetch_duration,
            rpc_fetch_errors,
            rpc_model_errors,
            nats_publish_errors,
        })
    }
}
