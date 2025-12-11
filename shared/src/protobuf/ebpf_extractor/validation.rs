use crate::bitcoin::hashes::Hash;
use crate::protobuf::ebpf_extractor::ctypes;
use std::fmt;

// structs are generated via the validation.proto file
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.validation.rs"));

impl From<ctypes::ValidationBlockConnected> for BlockConnected {
    fn from(connected: ctypes::ValidationBlockConnected) -> Self {
        BlockConnected {
            hash: connected.hash.to_vec(),
            height: connected.height,
            transactions: connected.transactions as i64,
            inputs: connected.inputs,
            sigops: connected.sigops as i64,
            connection_time: connected.connection_time,
        }
    }
}

impl fmt::Display for BlockConnected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockConnected(hash={}, height={}, transactions={}, inputs={}, sigops={}, time={}ns)",
            bitcoin::BlockHash::from_slice(&self.hash).unwrap(),
            self.height,
            self.transactions,
            self.inputs,
            self.sigops,
            self.connection_time,
        )
    }
}

impl fmt::Display for validation_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            validation_event::Event::BlockConnected(connected) => {
                write!(f, "{}", connected.to_string())
            }
        }
    }
}

impl fmt::Display for ValidationEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.event {
            Some(event) => write!(f, "{}", event),
            None => write!(f, "ValidationEvent(None)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use std::str::FromStr;

    #[test]
    fn test_display_format() {
        let hash_str = "0000000000000000000b4d0b25b0b2a3c8a8b8e8e9c4d7f5e5f4d3b2a1b0c0d0";
        let block_hash = BlockHash::from_str(hash_str).unwrap();
        let block = BlockConnected {
            hash: block_hash.to_byte_array().to_vec(),
            height: 680000,
            transactions: 2500,
            inputs: 4000,
            sigops: 8000,
            connection_time: 123456789,
        };

        let expected = format!(
            "BlockConnected(hash={}, height=680000, transactions=2500, inputs=4000, sigops=8000, time=123456789ns)",
            block_hash
        );

        assert_eq!(format!("{}", block), expected);
    }

    #[test]
    fn test_event_display_block_connected() {
        let hash_str = "0000000000000000000b4d0b25b0b2a3c8a8b8e8e9c4d7f5e5f4d3b2a1b0c0d0";
        let block_hash = BlockHash::from_str(hash_str).unwrap();
        let block_connected = BlockConnected {
            hash: block_hash.to_byte_array().to_vec(),
            height: 700000,
            transactions: 3000,
            inputs: 4500,
            sigops: 9000,
            connection_time: 987654321,
        };

        let event = validation_event::Event::BlockConnected(block_connected);

        let expected = format!(
            "BlockConnected(hash={}, height=700000, transactions=3000, inputs=4500, sigops=9000, time=987654321ns)",
            block_hash
        );

        assert_eq!(format!("{}", event), expected);
    }
}
