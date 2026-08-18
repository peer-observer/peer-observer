use crate::prost::Message;
use crate::util::current_timestamp;

use std::fmt;

// structs are generated via the archive/header.proto file
include!(concat!(env!("OUT_DIR"), "/header.rs"));

impl ArchiveHeader {
    pub fn new() -> Self {
        Self {
            created: current_timestamp(),
            low_data: Some(false),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_length_delimited_to_vec()
    }

    /// Unset in archives written before the field existed, which are full-data.
    pub fn is_low_data(&self) -> bool {
        self.low_data.unwrap_or(false)
    }
}

impl fmt::Display for ArchiveHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ArchiveHeader(created={}, low_data={})",
            self.created,
            self.is_low_data()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_low_data_is_full_data() {
        let header = ArchiveHeader {
            created: 1,
            low_data: None,
        };

        assert!(!header.is_low_data());
        assert_eq!(
            header.to_string(),
            "ArchiveHeader(created=1, low_data=false)"
        );
    }
}
