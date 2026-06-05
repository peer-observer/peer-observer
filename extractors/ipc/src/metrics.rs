use shared::anyhow::{Context, Result};
use shared::prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
};

const NAMESPACE: &str = "ipcextractor";

pub const LABEL_IPC_METHOD: &str = "ipc_method";

const IPC_DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Metrics for the ipc-extractor.
/// Each instance has its own registry.
#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: Registry,
    /// Time it took to fetch data from the IPC interface.
    pub ipc_fetch_duration: HistogramVec,
    /// Number of errors while fetching data from the IPC interface.
    pub ipc_fetch_errors: IntCounterVec,
    /// Number of errors while publishing events to NATS.
    pub nats_publish_errors: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new_custom(Some(NAMESPACE.to_string()), None)
            .context("creating prometheus registry")?;

        let ipc_fetch_duration = register_histogram_vec_with_registry!(
            HistogramOpts::new(
                "ipc_fetch_duration_seconds",
                "Time it took to fetch data from the IPC interface."
            )
            .buckets(IPC_DURATION_BUCKETS.to_vec()),
            &[LABEL_IPC_METHOD],
            registry
        )
        .context("creating ipc_fetch_duration_seconds metric")?;

        let ipc_fetch_errors = register_int_counter_vec_with_registry!(
            Opts::new(
                "ipc_fetch_errors_total",
                "Number of errors while fetching data from the IPC interface."
            ),
            &[LABEL_IPC_METHOD],
            registry
        )
        .context("creating ipc_fetch_errors_total metric")?;

        let nats_publish_errors = register_int_counter_vec_with_registry!(
            Opts::new(
                "nats_publish_errors_total",
                "Number of errors while publishing events to NATS."
            ),
            &[LABEL_IPC_METHOD],
            registry
        )
        .context("creating nats_publish_errors_total metric")?;

        Ok(Self {
            registry,
            ipc_fetch_duration,
            ipc_fetch_errors,
            nats_publish_errors,
        })
    }
}
