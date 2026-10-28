/// Protobuf types for the archives.
pub mod archive;

/// Protobuf types for some bitcoin primitives.
pub mod bitcoin_primitives;

/// Protobuf types for events.
pub mod event;

/// Protobuf types for ebpf-extractor events.
pub mod ebpf_extractor;

/// Protobuf types for p2p-extractor events.
pub mod p2p_extractor;

/// Protobuf types for rpc-extractor events.
pub mod rpc_extractor;

/// Protobuf types for ipc-extractor events.
pub mod ipc_extractor;

/// Protobuf types for log-extractor events.
pub mod log_extractor;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;

/// Formats the bytes of a hash field for display.
///
/// Hashes are `bytes` fields in the protobuf schema, so a decoded message
/// (from NATS, an archive, or elsewhere) can carry a field that isn't a valid
/// hash. Such fields are shown as hex instead of panicking.
pub fn display_hash<H: Hash>(bytes: &[u8]) -> String {
    match H::from_slice(bytes) {
        Ok(hash) => hash.to_string(),
        Err(_) => format!("invalid-hash({})", bytes.to_lower_hex_string()),
    }
}
