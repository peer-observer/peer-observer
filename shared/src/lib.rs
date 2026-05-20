#![cfg_attr(feature = "strict", deny(warnings))]

pub extern crate async_nats;
pub extern crate bitcoin;
pub extern crate bitcoind;
pub extern crate clap;
pub extern crate corepc_client;
pub extern crate futures;
pub extern crate lazy_static;
pub extern crate log;
pub extern crate prometheus;
pub extern crate prost;
pub extern crate rand;
pub extern crate serde;
pub extern crate simple_logger;
pub extern crate tokio;
pub extern crate tokio_util;
pub extern crate zstd;

/// Mappings and implementation for the protobuf types used in NATS
/// to communicate between the extractors and tools.
pub mod protobuf;

/// Subjects used when publishing and subscribing to NATS.
pub mod nats_subjects;

/// A minimal HTTP webserver (but not spec compliant) used to serve prometheus metrics via HTTP.
pub mod metricserver;

/// Used in integration testing.
pub mod testing;

/// Utillity functions shared among peer-observer tools
pub mod util;

/// Utillity functions for connecting to NATS servers.
pub mod nats_util;

/// Log matchers for the different types of log messages.
pub mod log_matchers;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
