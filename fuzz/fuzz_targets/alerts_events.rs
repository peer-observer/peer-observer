#![no_main]
//! Fuzzes the alerts tool's event handlers with a sequence of length-delimited
//! events, as they arrive over NATS. The tool keeps per-peer state, so the
//! order of events matters. Alerts are formatted instead of logged.

use alerts::{handle_event, Alert, AlertState, Alerter, Args};
use libfuzzer_sys::fuzz_target;
use shared::clap::Parser;
use shared::prost::Message;
use shared::protobuf::event::Event;
use std::sync::LazyLock;

/// The default command line arguments of the alerts tool.
static ARGS: LazyLock<Args> = LazyLock::new(|| Args::parse_from(["alerts"]));

/// Exercises the alert's Display implementation instead of logging it.
struct DisplayAlerter;

impl Alerter for DisplayAlerter {
    fn emit(&self, alert: Alert) {
        let _ = alert.to_string();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let mut state = AlertState::new();

    while !buf.is_empty() {
        let Ok(event) = Event::decode_length_delimited(&mut buf) else {
            break;
        };
        handle_event(event, &mut state, &ARGS, &DisplayAlerter);
    }
});
