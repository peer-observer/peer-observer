#![no_main]
//! Fuzzes the non-message ring buffer entries of the ebpf-extractor: the
//! connection, mempool, and validation structs. Each is read with the unsafe
//! `from_bytes`, converted to its protobuf type, and exercised.
//!
//! The first input byte selects the struct, the rest is the entry.

use libfuzzer_sys::fuzz_target;
use peer_observer_fuzz::layout::sanitize_mempool_replaced_entry;
use peer_observer_fuzz::{exercise_event, wrap_ebpf_event};
use shared::protobuf::ebpf_extractor::ctypes::{
    ClosedConnection, InboundConnection, MempoolAdded, MempoolRejected, MempoolRemoved,
    MempoolReplaced, MisbehavingConnection, OutboundConnection, ValidationBlockConnected,
};
use shared::protobuf::ebpf_extractor::{connection, ebpf, mempool, validation};
use std::mem::size_of;

/// Returns the first `size_of::<T>()` bytes, which is what the ring buffer
/// hands to the extractor for a struct of type `T`.
fn entry<T>(data: &[u8]) -> Option<Vec<u8>> {
    data.get(..size_of::<T>()).map(|e| e.to_vec())
}

fn connection_event(event: connection::connection_event::Event) {
    exercise_event(&wrap_ebpf_event(ebpf::EbpfEvent::Connection(
        connection::ConnectionEvent { event: Some(event) },
    )));
}

fn mempool_event(event: mempool::mempool_event::Event) {
    exercise_event(&wrap_ebpf_event(ebpf::EbpfEvent::Mempool(
        mempool::MempoolEvent { event: Some(event) },
    )));
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, data)) = data.split_first() else {
        return;
    };

    match kind % 10 {
        0 => {
            let Some(e) = entry::<ClosedConnection>(data) else {
                return;
            };
            let closed = ClosedConnection::from_bytes(&e);
            let _ = closed.to_string();
            connection_event(connection::connection_event::Event::Closed(closed.into()));
        }
        1 => {
            let Some(e) = entry::<ClosedConnection>(data) else {
                return;
            };
            let evicted = ClosedConnection::from_bytes(&e);
            let _ = evicted.to_string();
            connection_event(connection::connection_event::Event::InboundEvicted(
                evicted.into(),
            ));
        }
        2 => {
            let Some(e) = entry::<InboundConnection>(data) else {
                return;
            };
            let inbound = InboundConnection::from_bytes(&e);
            let _ = inbound.to_string();
            connection_event(connection::connection_event::Event::Inbound(inbound.into()));
        }
        3 => {
            let Some(e) = entry::<OutboundConnection>(data) else {
                return;
            };
            let outbound = OutboundConnection::from_bytes(&e);
            let _ = outbound.to_string();
            connection_event(connection::connection_event::Event::Outbound(
                outbound.into(),
            ));
        }
        4 => {
            let Some(e) = entry::<MisbehavingConnection>(data) else {
                return;
            };
            let misbehaving = MisbehavingConnection::from_bytes(&e);
            let _ = misbehaving.to_string();
            connection_event(connection::connection_event::Event::Misbehaving(
                misbehaving.into(),
            ));
        }
        5 => {
            let Some(e) = entry::<MempoolAdded>(data) else {
                return;
            };
            let added = MempoolAdded::from_bytes(&e);
            let _ = added.to_string();
            mempool_event(mempool::mempool_event::Event::Added(added.into()));
        }
        6 => {
            let Some(e) = entry::<MempoolRemoved>(data) else {
                return;
            };
            let removed = MempoolRemoved::from_bytes(&e);
            let _ = removed.to_string();
            mempool_event(mempool::mempool_event::Event::Removed(removed.into()));
        }
        7 => {
            let Some(mut e) = entry::<MempoolReplaced>(data) else {
                return;
            };
            sanitize_mempool_replaced_entry(&mut e);
            let replaced = MempoolReplaced::from_bytes(&e);
            let _ = replaced.to_string();
            mempool_event(mempool::mempool_event::Event::Replaced(replaced.into()));
        }
        8 => {
            let Some(e) = entry::<MempoolRejected>(data) else {
                return;
            };
            let rejected = MempoolRejected::from_bytes(&e);
            let _ = rejected.to_string();
            mempool_event(mempool::mempool_event::Event::Rejected(rejected.into()));
        }
        _ => {
            let Some(e) = entry::<ValidationBlockConnected>(data) else {
                return;
            };
            let connected = ValidationBlockConnected::from_bytes(&e);
            let _ = connected.to_string();
            exercise_event(&wrap_ebpf_event(ebpf::EbpfEvent::Validation(
                validation::ValidationEvent {
                    event: Some(validation::validation_event::Event::BlockConnected(
                        connected.into(),
                    )),
                },
            )));
        }
    }
});
