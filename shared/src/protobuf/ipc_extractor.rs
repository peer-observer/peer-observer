use crate::bitcoin::hashes::Hash;
use std::fmt;

// structs are generated via the ipc_extractor.proto file
include!(concat!(env!("OUT_DIR"), "/ipc_extractor.rs"));

impl fmt::Display for ipc::IpcEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ipc::IpcEvent::BlockTip(tip) => write!(f, "{}", tip),
        }
    }
}

impl fmt::Display for BlockTip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockTip(height={}, hash={})",
            self.height,
            bitcoin::BlockHash::from_slice(&self.hash).unwrap()
        )
    }
}
