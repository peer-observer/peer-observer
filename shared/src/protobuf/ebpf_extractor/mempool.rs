use crate::protobuf::ebpf_extractor::ctypes;
use bitcoin::hashes::Hash;
use std::fmt;

// structs are generated via the mempool.proto file
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.mempool.rs"));

impl From<ctypes::MempoolAdded> for Added {
    fn from(added: ctypes::MempoolAdded) -> Self {
        Added {
            txid: added.txid.to_vec(),
            vsize: added.vsize,
            fee: added.fee,
        }
    }
}

impl fmt::Display for Added {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Added({}, fee={}, vsize={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.fee,
            self.vsize,
        )
    }
}

impl From<ctypes::MempoolRemoved> for Removed {
    fn from(removed: ctypes::MempoolRemoved) -> Self {
        Removed {
            txid: removed.txid.to_vec(),
            reason: removed.reason(),
            vsize: removed.vsize,
            fee: removed.fee,
            entry_time: removed.entry_time,
        }
    }
}

impl fmt::Display for Removed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Removed({}, reason={}, vsize={}, fee={}, entry_time={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.reason,
            self.vsize,
            self.fee,
            self.entry_time,
        )
    }
}

impl From<ctypes::MempoolRejected> for Rejected {
    fn from(rejected: ctypes::MempoolRejected) -> Self {
        Rejected {
            txid: rejected.txid.to_vec(),
            reason: rejected.reason(),
        }
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Rejected({}, reason={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.reason,
        )
    }
}

impl fmt::Display for Replaced {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let replacement_id = if self.replaced_by_transaction {
            format!(
                "txid={}",
                bitcoin::Txid::from_slice(&self.replacement_id).unwrap()
            )
        } else {
            format!(
                "package_hash={}",
                bitcoin::Txid::from_slice(&self.replacement_id).unwrap()
            )
        };
        write!(
            f,
            "Replaced(old=(txid={}, vsize={}, fee={}, entry_time={}) new=({}, vsize={}, fee={}))",
            bitcoin::Txid::from_slice(&self.replaced_txid).unwrap(),
            self.replaced_vsize,
            self.replaced_fee,
            self.replaced_entry_time,
            replacement_id,
            self.replacement_vsize,
            self.replacement_fee,
        )
    }
}

impl From<ctypes::MempoolReplaced> for Replaced {
    fn from(replaced: ctypes::MempoolReplaced) -> Self {
        Replaced {
            replaced_txid: replaced.replaced_txid.to_vec(),
            replaced_vsize: replaced.replaced_vsize,
            replaced_fee: replaced.replaced_fee,
            replaced_entry_time: replaced.replaced_entry_time,
            replacement_id: replaced.replacement_id.to_vec(),
            replacement_vsize: replaced.replacement_vsize,
            replacement_fee: replaced.replacement_fee,
            replaced_by_transaction: replaced.replaced_by_transaction,
        }
    }
}

impl fmt::Display for mempool_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            mempool_event::Event::Added(added) => write!(f, "{}", added),
            mempool_event::Event::Removed(removed) => write!(f, "{}", removed),
            mempool_event::Event::Rejected(rejected) => write!(f, "{}", rejected),
            mempool_event::Event::Replaced(replaced) => write!(f, "{}", replaced),
        }
    }
}

impl fmt::Display for MempoolEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.event {
            Some(event) => write!(f, "{}", event),
            None => write!(f, "MempoolEvent(None)"),
        }
    }
}
