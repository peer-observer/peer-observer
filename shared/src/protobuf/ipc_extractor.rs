use crate::bitcoin::hashes::Hash;
use std::fmt;

// structs are generated via the ipc_extractor.proto file
include!(concat!(env!("OUT_DIR"), "/ipc_extractor.rs"));

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

impl fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockInfo(height={}, hash={}, prev_hash={})",
            self.height,
            bitcoin::BlockHash::from_slice(&self.hash).unwrap(),
            bitcoin::BlockHash::from_slice(&self.prev_hash).unwrap()
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

impl fmt::Display for TransactionAddedToMempool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TransactionAddedToMempool(txid={})",
            bitcoin::Txid::from_slice(&self.tx.txid).unwrap()
        )
    }
}

impl fmt::Display for TransactionRemovedFromMempool {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TransactionRemovedFromMempool(txid={}, reason={})",
            bitcoin::Txid::from_slice(&self.tx.txid).unwrap(),
            self.reason
        )
    }
}

impl fmt::Display for ChainStateFlushed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChainStateFlushed(role={}, locator_len={})",
            self.role,
            self.locator.len()
        )
    }
}

impl fmt::Display for ipc::IpcEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ipc::IpcEvent::BlockTip(t) => write!(f, "{}", t),
            ipc::IpcEvent::BlockConnected(b) => write!(f, "{}", b),
            ipc::IpcEvent::BlockDisconnected(b) => write!(f, "{}", b),
            ipc::IpcEvent::TransactionAddedToMempool(t) => write!(f, "{}", t),
            ipc::IpcEvent::TransactionRemovedFromMempool(t) => write!(f, "{}", t),
            ipc::IpcEvent::ChainStateFlushed(c) => write!(f, "{}", c),
        }
    }
}
