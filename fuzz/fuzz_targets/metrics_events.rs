#![no_main]
//! Fuzzes the metrics tool's event handlers with a sequence of
//! length-delimited events, as they arrive over NATS. The handlers keep state
//! between events (addrman diffs, compact block reconstruction), so the order
//! of events matters. A fresh registry and state are used per input to keep
//! runs deterministic and to stop label cardinality from growing without bound.

use libfuzzer_sys::fuzz_target;
use metrics::metrics::Metrics;
use metrics::{handle_decoded_event, State};
use shared::prost::Message;
use shared::protobuf::event::Event;
use std::sync::{Arc, Mutex};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let metrics = Metrics::new();
    let state = Arc::new(Mutex::new(State::default()));

    while !buf.is_empty() {
        let Ok(event) = Event::decode_length_delimited(&mut buf) else {
            break;
        };
        handle_decoded_event(event, state.clone(), metrics.clone());
    }
});
