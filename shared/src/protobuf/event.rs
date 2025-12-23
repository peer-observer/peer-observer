// The generated event module creates an event::event module.
// This isn't nice, but since we can't really control the inner one
// (due to being generated), allow it here. This avoids clippy from
// complaining about it.
#![allow(clippy::module_inception)]

use log::trace;
use std::time::SystemTime;
use std::time::SystemTimeError;

// structs are generated via the wrapper.proto file
include!(concat!(env!("OUT_DIR"), "/event.rs"));

impl Event {
    pub fn new(event: event::PeerObserverEvent) -> Result<Event, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        trace!("creating new Event: {:?}", event);
        Ok(Event {
            // We can store a UNIX epoch timestamp in millisecond precision
            // for more than the next 500.000 years..
            timestamp: now.as_millis() as u64,
            peer_observer_event: Some(event),
        })
    }
}
