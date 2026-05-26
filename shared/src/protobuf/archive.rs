use crate::prost::Message;
use crate::util::current_timestamp;

use std::fmt;

// structs are generated via the archive/header.proto file
include!(concat!(env!("OUT_DIR"), "/header.rs"));

impl ArchiveHeader {
    pub fn new() -> Self {
        Self {
            created: current_timestamp(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_length_delimited_to_vec()
    }
}

impl fmt::Display for ArchiveHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ArchiveHeader(created={})", self.created,)
    }
}
