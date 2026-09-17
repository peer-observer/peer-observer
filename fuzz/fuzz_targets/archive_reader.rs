#![no_main]
//! Fuzzes the archive file reader with arbitrary (uncompressed) archive bytes:
//! the length-delimited framing, the header, and every event read from it,
//! including the Display output the replayer prints. Archive files are the
//! one untrusted *file* input of the project.

use archive::read::ArchiveReader;
use libfuzzer_sys::fuzz_target;
use peer_observer_fuzz::exercise_event;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let reader = match ArchiveReader::new(Cursor::new(data)) {
        Ok(reader) => reader,
        Err(e) => {
            let _ = e.to_string();
            return;
        }
    };
    let _ = reader.header.to_string();
    let _ = reader.header.is_low_data();

    for event in reader {
        match event {
            Ok(event) => exercise_event(&event),
            Err(e) => {
                let _ = e.to_string();
                break;
            }
        }
    }
});
