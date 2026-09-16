use crate::protobuf::display_hash;
use crate::protobuf::ebpf_extractor::ctypes;
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
            display_hash::<bitcoin::Txid>(&self.txid),
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
            display_hash::<bitcoin::Txid>(&self.txid),
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
            display_hash::<bitcoin::Txid>(&self.txid),
            self.reason,
        )
    }
}

impl fmt::Display for Replaced {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let replacement_id = if self.replaced_by_transaction {
            format!(
                "txid={}",
                display_hash::<bitcoin::Txid>(&self.replacement_id)
            )
        } else {
            format!(
                "package_hash={}",
                display_hash::<bitcoin::Txid>(&self.replacement_id)
            )
        };
        write!(
            f,
            "Replaced(old=(txid={}, vsize={}, fee={}, entry_time={}) new=({}, vsize={}, fee={}))",
            display_hash::<bitcoin::Txid>(&self.replaced_txid),
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
