//! Helpers shared by the fuzz targets in `fuzz_targets/` and the seed
//! generator in `examples/gen_seeds.rs`.

use shared::bitcoin::p2p::message::NetworkMessage;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::message::{message_event, MessageEvent, Metadata};
use shared::protobuf::ebpf_extractor::{ebpf, Ebpf};
use shared::protobuf::event::{event::PeerObserverEvent, Event};

/// Layout helpers for the `#[repr(C)]` structs the ebpf-extractor reads from
/// the BPF ring buffers.
pub mod layout {
    use shared::protobuf::ebpf_extractor::ctypes::{MempoolReplaced, P2PMessageMetadata};
    use std::mem::{offset_of, size_of};

    /// Size of the metadata struct at the start of every P2P message ring
    /// buffer entry.
    pub const P2P_METADATA_SIZE: usize = size_of::<P2PMessageMetadata>();

    /// Builds a ring buffer entry for a P2P message: the metadata struct
    /// followed by the payload. Strings longer than their field are truncated.
    pub fn p2p_message_entry(
        peer_id: u64,
        peer_addr: &str,
        peer_conn_type: &str,
        msg_type: &str,
        inbound: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut entry = vec![0u8; P2P_METADATA_SIZE];
        write_field(
            &mut entry,
            offset_of!(P2PMessageMetadata, peer_id),
            &peer_id.to_ne_bytes(),
        );
        write_cstr(
            &mut entry,
            offset_of!(P2PMessageMetadata, peer_addr),
            68,
            peer_addr,
        );
        write_cstr(
            &mut entry,
            offset_of!(P2PMessageMetadata, peer_conn_type),
            20,
            peer_conn_type,
        );
        write_cstr(
            &mut entry,
            offset_of!(P2PMessageMetadata, msg_type),
            12,
            msg_type,
        );
        entry[offset_of!(P2PMessageMetadata, msg_inbound)] = inbound as u8;
        write_field(
            &mut entry,
            offset_of!(P2PMessageMetadata, msg_size),
            &(payload.len() as u64).to_ne_bytes(),
        );
        entry.extend_from_slice(payload);
        entry
    }

    /// Turns arbitrary fuzzer bytes into a P2P message ring buffer entry that
    /// respects the invariants the BPF program guarantees:
    ///
    /// - the entry is at least as large as the metadata struct,
    /// - `msg_inbound` is a valid `bool` (reading any other byte pattern as a
    ///   `bool` is undefined behavior, and the BPF side always writes 0 or 1),
    /// - the entry holds at least `msg_size` payload bytes (the BPF program
    ///   reserves a fixed-size struct and copies exactly `msg_size` bytes into
    ///   it).
    ///
    /// Everything else, including garbage in the string fields, is passed
    /// through untouched. Returns `None` if the input is too short.
    pub fn sanitize_p2p_message_entry(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < P2P_METADATA_SIZE {
            return None;
        }
        let mut entry = data.to_vec();
        let inbound = offset_of!(P2PMessageMetadata, msg_inbound);
        entry[inbound] &= 1;

        let size_offset = offset_of!(P2PMessageMetadata, msg_size);
        let mut size_bytes = [0u8; 8];
        size_bytes.copy_from_slice(&entry[size_offset..size_offset + 8]);
        let available = (entry.len() - P2P_METADATA_SIZE) as u64;
        let msg_size = u64::from_ne_bytes(size_bytes).min(available);
        write_field(&mut entry, size_offset, &msg_size.to_ne_bytes());
        Some(entry)
    }

    /// Clears all but the lowest bit of the `bool` field in a `MempoolReplaced`
    /// entry, for the same reason as in [`sanitize_p2p_message_entry`].
    pub fn sanitize_mempool_replaced_entry(entry: &mut [u8]) {
        entry[offset_of!(MempoolReplaced, replaced_by_transaction)] &= 1;
    }

    fn write_field(buf: &mut [u8], offset: usize, bytes: &[u8]) {
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Writes a NUL-terminated string into a fixed-size char array field.
    fn write_cstr(buf: &mut [u8], offset: usize, field_len: usize, s: &str) {
        let bytes = s.as_bytes();
        let n = bytes.len().min(field_len - 1);
        buf[offset..offset + n].copy_from_slice(&bytes[..n]);
        buf[offset + n] = 0;
    }
}

/// Runs an event through everything the tools do with it: the `Display`
/// implementations (logger, archive replayer), JSON serialization (websocket),
/// and a protobuf encode/decode round trip (NATS, archive).
pub fn exercise_event(event: &Event) {
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(e)) => {
            if let Some(inner) = &e.ebpf_event {
                let _ = inner.to_string();
            }
        }
        Some(PeerObserverEvent::RpcExtractor(r)) => {
            if let Some(inner) = &r.rpc_event {
                let _ = inner.to_string();
            }
        }
        Some(PeerObserverEvent::P2pExtractor(p)) => {
            if let Some(inner) = &p.p2p_event {
                let _ = inner.to_string();
            }
        }
        Some(PeerObserverEvent::LogExtractor(l)) => {
            if let Some(inner) = &l.log_event {
                let _ = inner.to_string();
            }
        }
        Some(PeerObserverEvent::IpcExtractor(i)) => {
            if let Some(inner) = &i.ipc_event {
                let _ = inner.to_string();
            }
        }
        None => {}
    }

    serde_json::to_string(event).expect("every event should serialize to JSON");

    let bytes = event.encode_to_vec();
    Event::decode(bytes.as_slice()).expect("a re-encoded event should decode again");
}

/// Wraps a peer-observer event in an [`Event`] with a fixed timestamp.
pub fn wrap_event(event: PeerObserverEvent) -> Event {
    Event {
        timestamp: 1_700_000_000_000,
        peer_observer_event: Some(event),
    }
}

/// Wraps an ebpf-extractor event in an [`Event`].
pub fn wrap_ebpf_event(event: ebpf::EbpfEvent) -> Event {
    wrap_event(PeerObserverEvent::EbpfExtractor(Ebpf {
        ebpf_event: Some(event),
    }))
}

/// Converts a decoded rust-bitcoin message the way the extractors do and
/// exercises the result.
pub fn exercise_network_message(meta: Metadata, msg: &NetworkMessage) {
    exercise_ebpf_message(meta, message_event::Msg::from(msg));
}

/// Exercises a P2P message event as produced by the ebpf-extractor.
pub fn exercise_ebpf_message(meta: Metadata, msg: message_event::Msg) {
    let _ = meta.to_string();
    let _ = msg.to_string();
    exercise_event(&wrap_ebpf_event(ebpf::EbpfEvent::Message(MessageEvent {
        meta,
        msg: Some(msg),
    })));
}

/// Metadata for messages that did not come through the ebpf-extractor.
pub fn dummy_metadata(command: &str, size: u64) -> Metadata {
    Metadata {
        peer_id: 0,
        addr: "127.0.0.1:8333".to_string(),
        conn_type: 0,
        command: command.to_string(),
        inbound: true,
        size,
    }
}
