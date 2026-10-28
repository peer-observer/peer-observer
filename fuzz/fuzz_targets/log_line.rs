#![no_main]
//! Fuzzes the debug.log line parser of the log-extractor. Bitcoin Core writes
//! some peer-supplied strings into its log, so lines are not fully trusted.

use libfuzzer_sys::fuzz_target;
use peer_observer_fuzz::{exercise_event, wrap_event};
use shared::log_matchers::parse_log_event;
use shared::protobuf::event::event::PeerObserverEvent;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };

    let log = parse_log_event(line);
    assert_eq!(log.log_line_bytes, line.len() as u64);

    exercise_event(&wrap_event(PeerObserverEvent::LogExtractor(log)));
});
