use log::trace;
use std::time::SystemTime;
use std::time::SystemTimeError;

// structs are generated via the wrapper.proto file
include!(concat!(env!("OUT_DIR"), "/event.rs"));

impl EventMsg {
    pub fn new(event: event_msg::Event) -> Result<EventMsg, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        trace!("creating new EventMsg with event: {:?}", event);
        Ok(EventMsg {
            // We can store a UNIX epoch timestamp in millisecond precision
            // for more than the next 500.000 years..
            timestamp: now.as_millis() as u64,
            event: Some(event),
        })
    }
}
