#![no_main]
//! Fuzzes the p2p-extractor's socket reader with arbitrary bytes, as a remote
//! peer would send them. This is the only place where an attacker talks to a
//! peer-observer binary directly. Every decoded message is then converted to
//! protobuf and exercised the way the extractor and tools do.

use libfuzzer_sys::fuzz_target;
use p2p_extractor::read_and_decode_message;
use peer_observer_fuzz::{dummy_metadata, exercise_network_message};
use shared::bitcoin::Network;
use shared::tokio::io::BufReader;

fuzz_target!(|data: &[u8]| {
    // `&[u8]` implements AsyncRead without needing a tokio runtime.
    let mut reader = BufReader::new(data);
    shared::futures::executor::block_on(async {
        loop {
            match read_and_decode_message(&mut reader, Network::Bitcoin, "fuzz").await {
                Ok(raw) => {
                    let payload = raw.payload();
                    exercise_network_message(dummy_metadata(payload.cmd(), 0), payload);
                }
                Err(e) => {
                    let _ = e.to_string();
                    break;
                }
            }
        }
    });
});
