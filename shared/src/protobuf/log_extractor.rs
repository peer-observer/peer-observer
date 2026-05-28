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

impl fmt::Display for SawNewHeaderLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SawNewHeader(hash={}, height={}, peer_id={}, is_compact_block={})",
            self.block_hash, self.block_height, self.peer_id, self.is_cmpctblock
        )
    }
}

impl fmt::Display for CompactBlockReconstructedLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompactBlockReconstructed(hash={}, prefilled={}, mempool={}, extra_pool={}, requested_count={}, requested_bytes={})",
            self.block_hash,
            self.prefilled_txn_count,
            self.mempool_txn_count,
            self.extra_pool_txn_count,
            self.requested_txn_count,
            self.requested_txn_bytes,
        )
    }
}

impl fmt::Display for log::LogEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            log::LogEvent::UnknownLogMessage(message) => write!(f, "{}", message),
            log::LogEvent::BlockConnectedLog(block) => write!(f, "{}", block),
            log::LogEvent::BlockCheckedLog(block) => {
                write!(f, "{}", block)
            }
            log::LogEvent::SawNewHeaderLog(header) => write!(f, "{}", header),
            log::LogEvent::CompactBlockReconstructedLog(reconstructed) => {
                write!(f, "{}", reconstructed)
            }
        }
    }
}
