/// Protobuf types for ebpf-extractor addrman tracepoint events.
pub mod addrman;
/// Protobuf types for ebpf-extractor mempool tracepoint events.
pub mod mempool;
/// Protobuf types for ebpf-extractor net connection tracepoint events.
pub mod net_conn;
/// Protobuf types for ebpf-extractor p2p message tracepoint events.
pub mod net_msg;
/// Protobuf types for ebpf-extractor validation tracepoint events.
pub mod validation;

/// Mapping from the ebpf C structs to the Rust protobuf structs.
pub mod ctypes;

use std::fmt;

// Generated types for ebpf_extractor.proto (EBPFEvent).
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.rs"));

impl fmt::Display for ebpf_event::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ebpf_event::Event::Msg(msg) => write!(f, "{}", msg),
            ebpf_event::Event::Conn(conn) => write!(f, "{}", conn),
            ebpf_event::Event::Addrman(addrman) => write!(f, "{}", addrman),
            ebpf_event::Event::Mempool(mempool) => write!(f, "{}", mempool),
            ebpf_event::Event::Validation(validation) => write!(f, "{}", validation),
        }
    }
}
