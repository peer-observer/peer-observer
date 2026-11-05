//! Prometheus metrics of the alerts tool: how often each alert kind fired,
//! when it last fired, and which peers are flagged right now.

use crate::alerter::Alert;
use shared::prometheus::{
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use shared::util;

const NAMESPACE: &str = "peerobserver";

pub const LABEL_ALERT: &str = "alert";
pub const LABEL_PEER_ID: &str = "peer_id";
pub const LABEL_ADDR: &str = "addr";

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    /// UNIX epoch timestamp of the tool start.
    pub runtime_start_timestamp: IntGauge,
    /// Number of alerts fired, by alert kind.
    pub alerts_total: IntCounterVec,
    /// UNIX epoch timestamp of the last alert, by alert kind. Zero if none.
    pub alerts_last_fired_timestamp: IntGaugeVec,
    /// Number of connected peers currently flagged, by alert kind.
    pub alerts_flagged_peers: IntGaugeVec,
    /// One series per flagged peer and alert kind, always 1. Removed when
    /// the peer disconnects.
    pub alerts_flagged_peer_info: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some(NAMESPACE.to_string()), None)
            .expect("Could not setup prometheus metric registry");

        let runtime_start_timestamp = register_int_gauge_with_registry!(
            Opts::new(
                "alerts_runtime_start_timestamp",
                "UNIX epoch timestamp of peer-observer alerts tool start."
            ),
            registry
        )
        .expect("Could not create metric 'alerts_runtime_start_timestamp'");

        let alerts_total = register_int_counter_vec_with_registry!(
            Opts::new("alerts_total", "Number of alerts fired, by alert kind."),
            &[LABEL_ALERT],
            registry
        )
        .expect("Could not create metric 'alerts_total'");

        let alerts_last_fired_timestamp = register_int_gauge_vec_with_registry!(
            Opts::new(
                "alerts_last_fired_timestamp",
                "UNIX epoch timestamp of the last alert, by alert kind. Zero if it never fired."
            ),
            &[LABEL_ALERT],
            registry
        )
        .expect("Could not create metric 'alerts_last_fired_timestamp'");

        let alerts_flagged_peers = register_int_gauge_vec_with_registry!(
            Opts::new(
                "alerts_flagged_peers",
                "Number of connected peers currently flagged, by alert kind. Kinds that are not about a single peer stay at zero."
            ),
            &[LABEL_ALERT],
            registry
        )
        .expect("Could not create metric 'alerts_flagged_peers'");

        let alerts_flagged_peer_info = register_int_gauge_vec_with_registry!(
            Opts::new(
                "alerts_flagged_peer_info",
                "A connected peer flagged by an alert kind. Always 1, removed when the peer disconnects."
            ),
            &[LABEL_ALERT, LABEL_PEER_ID, LABEL_ADDR],
            registry
        )
        .expect("Could not create metric 'alerts_flagged_peer_info'");

        // Create every series at zero so a kind that never fired still shows
        // up, and a first alert is a visible change from zero.
        for name in Alert::NAMES {
            alerts_total.with_label_values(&[name]).reset();
            alerts_last_fired_timestamp
                .with_label_values(&[name])
                .set(0);
            alerts_flagged_peers.with_label_values(&[name]).set(0);
        }

        Metrics {
            registry,
            runtime_start_timestamp,
            alerts_total,
            alerts_last_fired_timestamp,
            alerts_flagged_peers,
            alerts_flagged_peer_info,
        }
    }

    /// Counts a fired alert and notes when it fired.
    pub fn count(&self, alert: &Alert) {
        self.alerts_total.with_label_values(&[alert.name()]).inc();
        self.alerts_last_fired_timestamp
            .with_label_values(&[alert.name()])
            .set(util::current_timestamp() as i64);
    }

    /// Records that the alert kind `name` flagged the peer.
    pub fn peer_flagged(&self, name: &str, peer_id: u64, addr: &str) {
        self.alerts_flagged_peers.with_label_values(&[name]).inc();
        self.alerts_flagged_peer_info
            .with_label_values(&[name, &peer_id.to_string(), addr])
            .set(1);
    }

    /// Records that a peer flagged by the alert kind `name` is gone.
    pub fn peer_unflagged(&self, name: &str, peer_id: u64, addr: &str) {
        self.alerts_flagged_peers.with_label_values(&[name]).dec();
        // Fails only if the series does not exist, which is nothing to do.
        let _ =
            self.alerts_flagged_peer_info
                .remove_label_values(&[name, &peer_id.to_string(), addr]);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerter::SpammerKind;

    #[test]
    fn every_alert_kind_starts_at_zero_and_counts() {
        let metrics = Metrics::new();
        for name in Alert::NAMES {
            assert_eq!(metrics.alerts_total.with_label_values(&[name]).get(), 0);
            assert_eq!(
                metrics
                    .alerts_last_fired_timestamp
                    .with_label_values(&[name])
                    .get(),
                0
            );
        }
        metrics.count(&Alert::Spammer {
            kind: SpammerKind::Ping,
            peer_id: 1,
            addr: "1.2.3.4:8333".to_string(),
            count: 4,
            window_secs: 60,
            threshold: 3,
        });
        metrics.count(&Alert::TipRecovered {
            height: 1,
            stale_secs: 2,
        });
        assert_eq!(
            metrics
                .alerts_total
                .with_label_values(&["ping_spammer"])
                .get(),
            1
        );
        assert!(
            metrics
                .alerts_last_fired_timestamp
                .with_label_values(&["ping_spammer"])
                .get()
                > 0
        );
        assert_eq!(
            metrics
                .alerts_total
                .with_label_values(&["tip_recovered"])
                .get(),
            1
        );
        assert_eq!(
            metrics.alerts_total.with_label_values(&["stale_tip"]).get(),
            0
        );
    }

    #[test]
    fn flagged_peers_are_counted_while_connected() {
        let metrics = Metrics::new();
        metrics.peer_flagged("ping_spammer", 1, "1.2.3.4:8333");
        metrics.peer_flagged("ping_spammer", 2, "5.6.7.8:8333");
        assert_eq!(
            metrics
                .alerts_flagged_peers
                .with_label_values(&["ping_spammer"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .alerts_flagged_peer_info
                .with_label_values(&["ping_spammer", "1", "1.2.3.4:8333"])
                .get(),
            1
        );
        metrics.peer_unflagged("ping_spammer", 1, "1.2.3.4:8333");
        assert_eq!(
            metrics
                .alerts_flagged_peers
                .with_label_values(&["ping_spammer"])
                .get(),
            1
        );
        let text = shared::prometheus::TextEncoder::new()
            .encode_to_string(&metrics.registry.gather())
            .unwrap();
        assert!(!text.contains("peer_id=\"1\""), "removed series is gone");
        assert!(text.contains("peer_id=\"2\""));
    }
}
