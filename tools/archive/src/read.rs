use shared::prost::decode_length_delimiter;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::event::Event;
use shared::zstd;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read};
use std::path::Path;

#[derive(Debug)]
pub struct ArchiveReader<R> {
    reader: BufReader<R>,
    buf: Vec<u8>,
    pub header: ArchiveHeader,
}

impl ArchiveReader<Box<dyn Read>> {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;

        // TODO: we could detect the file type based on the ZSTD magic
        // being present or not..
        let reader: Box<dyn Read> = if path.extension() == Some(OsStr::new("zst")) {
            Box::new(zstd::Decoder::new(file)?)
        } else {
            Box::new(file)
        };

        Self::new(reader)
    }
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();

        let header = read_message(&mut reader, &mut buf)?
            .ok_or_else(|| io::Error::other("missing header"))?;

        Ok(Self {
            reader,
            buf,
            header,
        })
    }
}

impl<R: Read> Iterator for ArchiveReader<R> {
    type Item = io::Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        read_message(&mut self.reader, &mut self.buf).transpose()
    }
}

fn read_message<M: Message + Default>(
    reader: &mut impl Read,
    buf: &mut Vec<u8>,
) -> io::Result<Option<M>> {
    let len = match read_length_delimiter(reader)? {
        Some(len) => len,
        // A clean EOF at a message boundary is the normal end of the archive.
        None => return Ok(None),
    };

    buf.clear();
    buf.resize(len, 0);

    reader.read_exact(buf)?;

    let msg = M::decode(&buf[..]).map_err(io::Error::other)?;

    Ok(Some(msg))
}

/// Reads a protobuf varint length prefix from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at a message boundary (the normal end of
/// the archive); an EOF partway through the varint surfaces as `UnexpectedEof`.
///
/// Only a read returning `Ok(0)` counts as a clean EOF. Errors from the reader
/// are passed on, even at a message boundary: a zstd decoder reports an
/// incomplete frame as an `UnexpectedEof` error, which must not be mistaken
/// for the end of the archive.
///
/// prost only decodes a length delimiter from an in-memory `Buf`, so the prefix
/// has to be pulled off the stream first. Its encoded length is not known up
/// front, so we read one byte at a time until the varint's continuation bit
/// clears and hand the collected bytes to prost to decode.
fn read_length_delimiter(reader: &mut impl Read) -> io::Result<Option<usize>> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated length prefix",
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        bytes.push(byte[0]);

        // Stop once the continuation bit clears. Cap at the maximum varint
        // length so a malformed prefix can't make us read forever; prost then
        // rejects it.
        if byte[0] & 0x80 == 0 || bytes.len() == 10 {
            break;
        }
    }

    decode_length_delimiter(&mut bytes.as_slice())
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Yields at most one byte per `read`, so a multi-byte length prefix
    /// arrives split across several reads.
    struct Trickle<R>(R);

    impl<R: Read> Read for Trickle<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    #[test]
    fn reads_single_byte_length_prefix() {
        let mut reader = Cursor::new(vec![0x05]);
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some(5));
    }

    #[test]
    fn reads_multi_byte_length_prefix_split_across_reads() {
        // 300 encodes as the two-byte varint [0xAC, 0x02]. A prefix split across
        // reads must still decode to the full value.
        let mut reader = Trickle(Cursor::new(vec![0xAC, 0x02]));
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some(300));
    }

    #[test]
    fn returns_none_on_clean_eof_at_boundary() {
        let mut reader = Cursor::new(Vec::new());
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), None);
    }

    #[test]
    fn errors_on_truncated_length_prefix() {
        // A lone continuation byte with no follow-up is a truncated varint.
        let mut reader = Cursor::new(vec![0x80]);
        let err = read_length_delimiter(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn errors_on_reader_error_at_boundary() {
        // A reader error at a message boundary is not a clean EOF, even when
        // it is an UnexpectedEof.
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(ErrorKind::UnexpectedEof, "incomplete frame"))
            }
        }
        let err = read_length_delimiter(&mut FailingReader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    fn test_event() -> Event {
        Event {
            timestamp: 1,
            ..Default::default()
        }
    }

    fn compressed_archive(finish: bool) -> Vec<u8> {
        use std::io::Write;

        let mut bytes = ArchiveHeader::default().encode_length_delimited_to_vec();
        test_event().encode_length_delimited(&mut bytes).unwrap();
        let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(&bytes).unwrap();
        if finish {
            encoder.finish().unwrap()
        } else {
            // Flushed but never finished, like an archiver that was killed.
            encoder.flush().unwrap();
            encoder.get_ref().clone()
        }
    }

    #[test]
    fn reads_finished_zstd_archive() {
        let decoder = zstd::Decoder::new(Cursor::new(compressed_archive(true))).unwrap();
        let mut archive = ArchiveReader::new(decoder).unwrap();
        assert_eq!(archive.next().unwrap().unwrap(), test_event());
        assert!(archive.next().is_none());
    }

    #[test]
    fn errors_on_incomplete_zstd_frame() {
        let decoder = zstd::Decoder::new(Cursor::new(compressed_archive(false))).unwrap();
        let mut archive = ArchiveReader::new(decoder).unwrap();
        // Events before the truncation are still returned.
        assert_eq!(archive.next().unwrap().unwrap(), test_event());
        let err = archive
            .next()
            .expect("an incomplete frame should not look like a clean EOF")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_message_returns_none_on_clean_eof() {
        let mut reader = BufReader::new(Cursor::new(Vec::new()));
        let mut buf = Vec::new();
        let msg: Option<ArchiveHeader> = read_message(&mut reader, &mut buf).unwrap();
        assert!(msg.is_none());
    }
}
