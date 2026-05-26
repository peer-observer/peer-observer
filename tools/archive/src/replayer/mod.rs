use std::ffi::OsStr;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::path::Path;

use shared::prost::decode_length_delimiter;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::event::Event;
use shared::zstd;

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

    let mut data = &buf[..];
    let mut cursor = 0;
    let mut events = Vec::new();

    let payload_len = decode_length_delimiter(&mut data)
        .map_err(|e| Error::other(format!("bad length at byte {cursor}: {e}")))?;
    let varint_len = (data.len() - cursor) - data.len();
    let header =
        ArchiveHeader::decode(&data[cursor + varint_len..cursor + varint_len + payload_len])
            .map_err(|e| Error::other(format!("decode error at byte {cursor}: {e}")))?;
    cursor += varint_len + payload_len;

    while cursor < data.len() {
        let mut wire = &data[cursor..];
        let payload_len = decode_length_delimiter(&mut wire)
            .map_err(|e| Error::other(format!("bad length at byte {cursor}: {e}")))?;
        let varint_len = (data.len() - cursor) - wire.len();
        let event = Event::decode(&data[cursor + varint_len..cursor + varint_len + payload_len])
            .map_err(|e| Error::other(format!("decode error at byte {cursor}: {e}")))?;
        cursor += varint_len + payload_len;
        events.push(event);
    }

    Ok(Archive { header, events })
}
