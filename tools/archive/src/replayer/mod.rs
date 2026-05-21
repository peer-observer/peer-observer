use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use shared::prost::Message;
use shared::protobuf::event::Event;
use shared::zstd;

const HEADER_SIZE: usize = 16;

pub struct ArchiveHeader {
    pub version: u8,
    pub git_hash: [u8; 4],
}

pub struct Archive {
    pub header: ArchiveHeader,
    pub events: Vec<Event>,
}

pub fn read_archive(path: &Path) -> std::io::Result<Archive> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    if path.extension() == Some(OsStr::new("zst")) {
        zstd::Decoder::new(file)?.read_to_end(&mut buf)?;
    } else {
        file.read_to_end(&mut buf)?;
    }

    if buf.len() < HEADER_SIZE {
        return Err(std::io::Error::other(format!(
            "file too small: {} bytes",
            buf.len()
        )));
    }

    if &buf[0..2] != b"PA" {
        return Err(std::io::Error::other(format!(
            "invalid magic: {:02x}{:02x} (expected \"PA\")",
            buf[0], buf[1]
        )));
    }

    let header = ArchiveHeader {
        version: buf[2],
        git_hash: [buf[3], buf[4], buf[5], buf[6]],
    };

    let data = &buf[HEADER_SIZE..];
    let mut cursor = 0;
    let mut events = Vec::new();

    while cursor < data.len() {
        let mut wire = &data[cursor..];
        let payload_len = shared::prost::decode_length_delimiter(&mut wire)
            .map_err(|e| std::io::Error::other(format!("bad length at byte {cursor}: {e}")))?;
        let varint_len = (data.len() - cursor) - wire.len();
        let event = Event::decode(&data[cursor + varint_len..cursor + varint_len + payload_len])
            .map_err(|e| std::io::Error::other(format!("decode error at byte {cursor}: {e}")))?;
        cursor += varint_len + payload_len;
        events.push(event);
    }

    Ok(Archive { header, events })
}
