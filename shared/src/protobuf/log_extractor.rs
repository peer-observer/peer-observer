use std::fmt;

// structs are generated via the log_extractor.proto file
include!(concat!(env!("OUT_DIR"), "/log_extractor.rs"));

impl fmt::Display for UnknownLogMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnknownLogMessage({})", self.raw_message)
    }
}

impl fmt::Display for BlockConnectedLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockConnected(hash={}, height={})",
            self.block_hash, self.block_height
        )
    }
}

impl fmt::Display for BlockCheckedLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockChecked(hash={}, state={}, debug_message={})",
            self.block_hash, self.state, self.debug_message
        )
    }
}

impl fmt::Display for log_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            log_event::Event::UnknownLogMessage(message) => write!(f, "{}", message),
            log_event::Event::BlockConnectedLog(block) => write!(f, "{}", block),
            log_event::Event::BlockCheckedLog(block) => {
                write!(f, "{}", block)
            }
        }
    }
}
