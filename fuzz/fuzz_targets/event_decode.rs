#![no_main]
//! Fuzzes protobuf decoding of a single `Event` followed by everything the
//! tools do with a decoded event (Display, JSON, re-encoding). This covers what
//! every NATS consumer (logger, metrics, websocket, alerts, archive) runs on
//! each received message, without the archive framing in between.

use libfuzzer_sys::fuzz_target;
use peer_observer_fuzz::exercise_event;
use shared::prost::Message;
use shared::protobuf::event::Event;

fuzz_target!(|data: &[u8]| {
    if let Ok(event) = Event::decode(data) {
        exercise_event(&event);
    }
});
