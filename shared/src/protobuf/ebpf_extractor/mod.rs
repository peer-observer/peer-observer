/// Protobuf types for ebpf-extractor addrman tracepoint events.
pub mod addrman;
/// Protobuf types for ebpf-extractor mempool tracepoint events.
pub mod mempool;
/// Protobuf types for ebpf-extractor connection tracepoint events.
pub mod connection;
/// Protobuf types for ebpf-extractor p2p message tracepoint events.
pub mod net_msg;
/// Protobuf types for ebpf-extractor validation tracepoint events.
pub mod validation;

/// Mapping from the ebpf C structs to the Rust protobuf structs.
pub mod ctypes;

use std::fmt;

// Generated types for ebpf_extractor.proto (EBPFEvent).
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.rs"));

impl fmt::Display for ebpf::EbpfEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ebpf::EbpfEvent::Msg(msg) => write!(f, "{}", msg),
            ebpf::EbpfEvent::Connection(connection) => write!(f, "{}", connection),
            ebpf::EbpfEvent::Addrman(addrman) => write!(f, "{}", addrman),
            ebpf::EbpfEvent::Mempool(mempool) => write!(f, "{}", mempool),
            ebpf::EbpfEvent::Validation(validation) => write!(f, "{}", validation),
        }
    }
}
