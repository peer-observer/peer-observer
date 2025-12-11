use crate::protobuf::ebpf_extractor::ctypes;
use std::fmt;

// structs are generated via the addrman.proto file
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.addrman.rs"));

impl From<ctypes::AddrmanInsertNew> for InsertNew {
    fn from(new: ctypes::AddrmanInsertNew) -> Self {
        InsertNew {
            inserted: new.inserted,
            bucket: new.bucket,
            bucket_pos: new.bucket_pos,
            addr: new.addr(),
            addr_as: new.addr_as,
            source: new.source(),
            source_as: new.source_as,
        }
    }
}

impl fmt::Display for InsertNew {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "InsertNew(inserted={}, bucket={}, bucket_pos={}, addr={}, addr_AS={}, source={}, source_AS={})",
            self.inserted, self.bucket, self.bucket_pos, self.addr, self.addr_as, self.source, self.source_as,
        )
    }
}

impl From<ctypes::AddrmanInsertTried> for InsertTried {
    fn from(tried: ctypes::AddrmanInsertTried) -> Self {
        InsertTried {
            bucket: tried.bucket,
            bucket_pos: tried.bucket_pos,
            addr: tried.addr(),
            addr_as: tried.addr_as,
            source: tried.source(),
            source_as: tried.source_as,
        }
    }
}

impl fmt::Display for InsertTried {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "InsertTried(bucket={}, bucket_pos={}, addr={}, addr_AS={}, source={}, source_AS={})",
            self.bucket, self.bucket_pos, self.addr, self.addr_as, self.source, self.source_as,
        )
    }
}

impl fmt::Display for addrman_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            addrman_event::Event::New(new) => write!(f, "{}", new),
            addrman_event::Event::Tried(tried) => write!(f, "{}", tried),
        }
    }
}

impl fmt::Display for AddrmanEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.event {
            Some(event) => write!(f, "{}", event),
            None => write!(f, "AddrmanEvent(None)"),
        }
    }
}
