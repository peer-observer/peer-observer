use log::trace;
use std::time::SystemTime;
use std::time::SystemTimeError;

// structs are generated via the wrapper.proto file
include!(concat!(env!("OUT_DIR"), "/event.rs"));

impl EventMsg {
    pub fn new(event: event_msg::Event) -> Result<EventMsg, SystemTimeError> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let timestamp = now.as_secs();
        let timestamp_subsec_micros = now.subsec_micros();
        trace!("creating new EventMsg with event: {:?}", event);
        Ok(EventMsg {
            timestamp,
            timestamp_subsec_micros,
            event: Some(event),
        })
    }
}
