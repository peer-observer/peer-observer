use shared::prost::decode_length_delimiter;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::event::Event;
use shared::zstd;
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufRead;
use std::io::{self, BufReader, Read};
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
    reader: &mut impl BufRead,
    buf: &mut Vec<u8>,
) -> io::Result<Option<M>> {
    let available = reader.fill_buf()?;

    if available.is_empty() {
        return Ok(None);
    }

    let mut slice = available;

    let len = decode_length_delimiter(&mut slice).map_err(io::Error::other)?;

    let varint_len = available.len() - slice.len();

    reader.consume(varint_len);

    buf.clear();
    buf.resize(len, 0);

    reader.read_exact(buf)?;

    let msg = M::decode(&buf[..]).map_err(io::Error::other)?;

    Ok(Some(msg))
}
