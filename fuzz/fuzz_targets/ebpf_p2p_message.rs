#![no_main]
//! Fuzzes the path a P2P message takes through the ebpf-extractor: the unsafe
//! struct read in `P2PMessage::from_bytes`, the rust-bitcoin decode of the
//! payload, the protobuf conversion, and the Display / JSON output the tools
//! produce from it.
//!
//! The input is a raw ring buffer entry: a `P2PMessageMetadata` struct followed
//! by the payload bytes. Message payloads and peer address strings originate
//! from remote peers, so this is the main untrusted input of the project.

use libfuzzer_sys::fuzz_target;
use peer_observer_fuzz::exercise_ebpf_message;
use peer_observer_fuzz::layout::sanitize_p2p_message_entry;
use shared::protobuf::ebpf_extractor::ctypes::P2PMessage;

fuzz_target!(|data: &[u8]| {
    let Some(entry) = sanitize_p2p_message_entry(data) else {
        return;
    };

    let message = P2PMessage::from_bytes(&entry);
    let _ = message.meta.to_string();
    let meta = message.meta.create_protobuf_metadata();

    match message.decode_to_protobuf_network_message() {
        Ok(msg) => exercise_ebpf_message(meta, msg),
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
