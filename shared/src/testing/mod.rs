use std::str::FromStr;
use std::sync::LazyLock;

use crate::bitcoin::{address::Address, Network};

/// Static regtest address for integration tests initalized statically for global scope
pub static REGTEST_ADDRESS: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
        .expect("valid bech32")
        .require_network(Network::Regtest)
        .expect("regtest address")
});

/// Utilities for fetching Prometheus metrics in integration tests.
pub mod metrics_fetcher;
/// A NATS publisher to be used in integration tests.
pub mod nats_publisher;
/// A NATS server runnner to be used in integration tests.
pub mod nats_server;
