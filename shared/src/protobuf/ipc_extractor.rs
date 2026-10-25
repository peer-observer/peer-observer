use crate::bitcoin::hashes::Hash;
use bitcoin::hex::*;
use std::fmt;

// structs are generated via the ipc_extractor.proto file
include!(concat!(env!("OUT_DIR"), "/ipc_extractor.rs"));

impl fmt::Display for ipc::IpcEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ipc::IpcEvent::BlockTip(tip) => write!(f, "{}", tip),
            ipc::IpcEvent::TransactionAddedToMempool(added) => write!(f, "{}", added),
            ipc::IpcEvent::TransactionRemovedFromMempool(removed) => write!(f, "{}", removed),
            ipc::IpcEvent::BlockConnected(connected) => write!(f, "{}", connected),
            ipc::IpcEvent::BlockDisconnected(disconnected) => write!(f, "{}", disconnected),
            ipc::IpcEvent::UpdatedBlockTip(updated) => write!(f, "{}", updated),
            ipc::IpcEvent::ChainStateFlushed(flushed) => write!(f, "{}", flushed),
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

impl fmt::Display for TransactionAddedToMempool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TransactionAddedToMempool(tx={})", self.tx)
    }
}

impl fmt::Display for TransactionRemovedFromMempool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TransactionRemovedFromMempool(tx={}, reason={})",
            self.tx, self.reason
        )
    }
}

impl fmt::Display for BlockConnected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockConnected(role={}, block={})",
            self.role, self.block
        )
    }
}

impl fmt::Display for BlockDisconnected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockDisconnected(block={})", self.block)
    }
}

impl fmt::Display for UpdatedBlockTip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UpdatedBlockTip()")
    }
}

impl fmt::Display for ChainStateFlushed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChainStateFlushed(role={}, locator={})",
            self.role,
            self.locator.to_lower_hex_string()
        )
    }
}

impl fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockInfo(hash={}, prev_hash={}, height={}, chain_time_max={})",
            bitcoin::BlockHash::from_slice(&self.hash).unwrap(),
            match &self.prev_hash {
                Some(hash) => bitcoin::BlockHash::from_slice(hash).unwrap().to_string(),
                None => String::from("unknown"),
            },
            self.height,
            self.chain_time_max
        )
    }
}

impl fmt::Display for ChainstateRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChainstateRole(validated={}, historical={})",
            self.validated, self.historical
        )
    }
}
