/// The overarching Event message.
pub mod event_msg;

/// Mapping from the ebpf C structs to the Rust protobuf structs.
pub mod ctypes;

/// Protobuf type Bitcoin primitives for some of the ebpf-extractor events.
pub mod primitive;

pub mod addrman;
/// Protobuf types for ebpf-extractor mempool tracepoint events.
pub mod mempool;
/// Protobuf types for ebpf-extractor net connection tracepoint events.
pub mod net_conn;
/// Protobuf types for ebpf-extractor p2p message tracepoint events.
pub mod net_msg;
/// Protobuf types for ebpf-extractor validation tracepoint events.
pub mod validation;

/// Protobuf types for p2p-extractor events.
pub mod p2p_extractor;

/// Protobuf types for rpc-extractor events.
pub mod rpc_extractor;

/// Protobuf types for log-extractor events.
pub mod log_extractor;
