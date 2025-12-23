use std::{cmp, fmt, mem, ptr};

use bitcoin::consensus::{self, Decodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::hex::*;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};

use crate::protobuf::bitcoin_primitives::ConnType;
use crate::protobuf::ebpf_extractor::message;

// Tor v3 addresses are 62 chars + 6 chars for the port (':12345').
const MAX_PEER_ADDR_LENGTH: usize = 62 + 6;
const MAX_PEER_CONN_TYPE_LENGTH: usize = 20;
const MAX_MSG_TYPE_LENGTH: usize = 12;
const MAX_MISBEHAVING_MESSAGE_LENGTH: usize = 128;

/// Based on Bitcoin Core's MAX_PROTOCOL_MESSAGE_LENGTH. Longer messages are rejected.
const MAX_P2P_MESSAGE_SIZE: usize = 4194304; // 4 MB

const TXID_LENGTH: usize = 32;
const REMOVAL_REASON_LENGTH: usize = 9;
const REJECTION_REASON_LENGTH: usize = 118;
const HASH_LENGTH: usize = 32;

/// The metadata for a P2P message.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct P2PMessageMetadata {
    pub peer_id: u64,
    pub peer_addr: [u8; MAX_PEER_ADDR_LENGTH],
    pub peer_conn_type: [u8; MAX_PEER_CONN_TYPE_LENGTH],
    pub msg_type: [u8; MAX_MSG_TYPE_LENGTH],
    pub msg_inbound: bool,
    pub msg_size: u64,
}

impl P2PMessageMetadata {
    /// Extracts the IP address of the peer as a string from the addr bytes.
    pub fn peer_addr(&self) -> String {
        String::from_utf8_lossy(self.peer_addr.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    /// Extracts the connection type of the peer as a string from the peer_conn_type bytes.
    pub fn peer_conn_type(&self) -> String {
        String::from_utf8_lossy(self.peer_conn_type.split(|c| *c == 0x00u8).next().unwrap())
            .into_owned()
    }

    /// Extracts the type (i.e. command) of the message  as a string from the msg_type bytes.
    pub fn msg_type(&self) -> String {
        String::from_utf8_lossy(self.msg_type.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    pub fn from_bytes(x: &[u8]) -> Self {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const Self) }
    }

    pub fn create_protobuf_metadata(&self) -> message::Metadata {
        let conn_type: ConnType = self.peer_conn_type().into();

        message::Metadata {
            peer_id: self.peer_id,
            addr: self.peer_addr(),
            conn_type: conn_type as i32,
            command: self.msg_type(),
            inbound: self.msg_inbound,
            size: self.msg_size,
        }
    }
}

impl fmt::Display for P2PMessageMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-msg ({} bytes) {} peer (id={}, addr={}, conntype={})",
            self.msg_type(),
            self.msg_size,
            if self.msg_inbound { "from" } else { "to" },
            self.peer_id,
            self.peer_addr(),
            self.peer_conn_type(),
        )
    }
}

pub struct P2PMessage {
    pub meta: P2PMessageMetadata,
    pub payload: Vec<u8>,
}

impl P2PMessage {
    pub fn from_bytes(x: &[u8]) -> P2PMessage {
        const SIZEOF_METADATA_STRUCT: usize = mem::size_of::<P2PMessageMetadata>();
        let meta_bytes = &x[..SIZEOF_METADATA_STRUCT];
        let meta = unsafe { ptr::read_unaligned(meta_bytes.as_ptr() as *const P2PMessageMetadata) };
        let payload_size = cmp::min(meta.msg_size as usize, MAX_P2P_MESSAGE_SIZE);
        let payload = x[SIZEOF_METADATA_STRUCT..SIZEOF_METADATA_STRUCT + payload_size].to_vec();
        P2PMessage { meta, payload }
    }

    pub fn decode_to_protobuf_network_message(
        &self,
    ) -> Result<message::message_event::Msg, P2PMessageDecodeError> {
        decode_network_message(&self.meta, &self.payload)
    }
}

#[repr(C)]
pub struct Connection {
    pub id: u64,
    pub addr: [u8; MAX_PEER_ADDR_LENGTH],
    pub conn_type: [u8; MAX_PEER_CONN_TYPE_LENGTH],
    pub network: u32,
}

impl Connection {
    /// Extracts the IP address of the peer as a string from the addr bytes.
    pub fn addr(&self) -> String {
        String::from_utf8_lossy(self.addr.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    /// Extracts the connection type of the peer as a string from the conn_type bytes.
    pub fn conn_type(&self) -> String {
        String::from_utf8_lossy(self.conn_type.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Connection(peer={}, addr={}, type={}, network={})",
            self.id,
            self.addr(),
            self.conn_type(),
            self.network,
        )
    }
}

#[repr(C)]
pub struct ClosedConnection {
    /// The connection being closed
    pub connection: Connection,
    /// Connection established UNIX epoch timestamp
    pub time_established: u64,
}

impl fmt::Display for ClosedConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ClosedConnection(conn={}, time_established={})",
            self.connection, self.time_established,
        )
    }
}

impl ClosedConnection {
    pub fn from_bytes(x: &[u8]) -> ClosedConnection {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const ClosedConnection) }
    }
}

#[repr(C)]
pub struct InboundConnection {
    /// The inbound connection being opened
    pub connection: Connection,
    /// Number of inbound connections existing (not including this newly opened one)
    pub existing_connections: u64,
}

impl InboundConnection {
    pub fn from_bytes(x: &[u8]) -> InboundConnection {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const InboundConnection) }
    }
}

impl fmt::Display for InboundConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "InboundConnection(conn={}, existing_connections={})",
            self.connection, self.existing_connections,
        )
    }
}

#[repr(C)]
pub struct OutboundConnection {
    /// The outbound connection being opened
    pub connection: Connection,
    /// Number of outbound connections existing (not including this newly opened one)
    pub existing_connections: u64,
}

impl OutboundConnection {
    pub fn from_bytes(x: &[u8]) -> OutboundConnection {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const OutboundConnection) }
    }
}

impl fmt::Display for OutboundConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OutboundConnection(conn={}, existing_connections={})",
            self.connection, self.existing_connections
        )
    }
}

#[repr(C)]
pub struct MisbehavingConnection {
    pub id: u64,
    pub message: [u8; MAX_MISBEHAVING_MESSAGE_LENGTH],
}

impl MisbehavingConnection {
    pub fn from_bytes(x: &[u8]) -> MisbehavingConnection {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const MisbehavingConnection) }
    }

    /// Extracts the misbehavior message as a string from the message bytes.
    pub fn message(&self) -> String {
        String::from_utf8_lossy(self.message.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }
}

impl fmt::Display for MisbehavingConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MisbehavingConnection(id={}, message={})",
            self.id,
            self.message(),
        )
    }
}

#[repr(C)]
pub struct MempoolAdded {
    /// Txid of the added transaction
    pub txid: [u8; TXID_LENGTH],
    /// Vsize of the added transaction
    pub vsize: i32,
    /// Fee of the added transaction
    pub fee: i64,
}

impl fmt::Display for MempoolAdded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MempoolAdded(txid={}, vsize={}, fee={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.vsize,
            self.fee,
        )
    }
}

impl MempoolAdded {
    pub fn from_bytes(x: &[u8]) -> MempoolAdded {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const MempoolAdded) }
    }
}

#[repr(C)]
pub struct MempoolRemoved {
    /// Txid of the removed transaction
    pub txid: [u8; TXID_LENGTH],
    /// Removal reason of the transaction
    pub reason: [u8; REMOVAL_REASON_LENGTH],
    /// Virtual size of the removed transaction
    pub vsize: i32,
    /// Fee of the removed transaction
    pub fee: i64,
    /// Mempool entry time of the removed transaction.
    pub entry_time: u64,
}

impl fmt::Display for MempoolRemoved {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MempoolRemoved(txid={}, reason={}, vsize={}, fee={}, entry_time={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.reason(),
            self.vsize,
            self.fee,
            self.entry_time,
        )
    }
}

impl MempoolRemoved {
    /// Returns the removal reason as String
    pub fn reason(&self) -> String {
        String::from_utf8_lossy(self.reason.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    pub fn from_bytes(x: &[u8]) -> MempoolRemoved {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const MempoolRemoved) }
    }
}

#[repr(C)]
pub struct MempoolReplaced {
    /// Txid of the replaced transaction
    pub replaced_txid: [u8; TXID_LENGTH],
    /// Virtual size of the replaced transaction
    pub replaced_vsize: i32,
    /// Fee of the replaced transaction
    pub replaced_fee: i64,
    /// Mempool entry time of the replaced transaction.
    pub replaced_entry_time: u64,
    /// Txid of the replacement transaction or package (as determined by replaced_by_transaction)
    pub replacement_id: [u8; TXID_LENGTH],
    /// Virtual size of the replacement transaction
    pub replacement_vsize: i32,
    /// Fee of the replaced transaction
    pub replacement_fee: i64,
    /// Boolean indicating if replacement_id is a transaction ID (true) or package hash (false)
    pub replaced_by_transaction: bool,
}

impl MempoolReplaced {
    pub fn from_bytes(x: &[u8]) -> MempoolReplaced {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const MempoolReplaced) }
    }
}

impl fmt::Display for MempoolReplaced {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let replacement_id = if self.replaced_by_transaction {
            format!(
                "txid={}",
                bitcoin::Txid::from_slice(&self.replacement_id).unwrap()
            )
        } else {
            format!(
                "package_hash={}",
                bitcoin::Txid::from_slice(&self.replacement_id).unwrap()
            )
        };
        write!(
            f,
            "MempoolReplaced(old(txid={}, vsize={}, fee={}, entry_time={}), new({}, vsize={}, fee={}))",
            bitcoin::Txid::from_slice(&self.replaced_txid).unwrap(),
            self.replaced_vsize,
            self.replaced_fee,
            self.replaced_entry_time,
            replacement_id,
            self.replacement_vsize,
            self.replacement_fee,
        )
    }
}

#[repr(C)]
pub struct MempoolRejected {
    /// Txid of the added transaction
    pub txid: [u8; TXID_LENGTH],
    /// Reason why the transaction was rejected
    pub reason: [u8; REJECTION_REASON_LENGTH],
}

impl fmt::Display for MempoolRejected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MempoolRejected(txid={}, reason={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            self.reason(),
        )
    }
}

impl MempoolRejected {
    /// Returns the rejection reason as String
    pub fn reason(&self) -> String {
        String::from_utf8_lossy(self.reason.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    pub fn from_bytes(x: &[u8]) -> MempoolRejected {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const MempoolRejected) }
    }
}

#[repr(C)]
pub struct ValidationBlockConnected {
    /// Hash of the connected block
    pub hash: [u8; HASH_LENGTH],
    /// Height of the connected block
    pub height: i32,
    /// Number of transactions in the connected block
    pub transactions: u64,
    /// Number of inputs in the connected block
    pub inputs: i32,
    /// Number of sigops in the connected block
    pub sigops: u64,
    /// Time it took to connect the block in microseconds (µs)
    pub connection_time: u64,
}

impl fmt::Display for ValidationBlockConnected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ValidationBlockConnected(hash={}, height={}, transactions={}, inputs={}, sigops={}, time={}µs)",
            bitcoin::BlockHash::from_slice(&self.hash).unwrap(),
            self.height, self.transactions, self.inputs, self.sigops, self.connection_time,
        )
    }
}

impl ValidationBlockConnected {
    pub fn from_bytes(x: &[u8]) -> Self {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const Self) }
    }
}

fn decode_network_message(
    meta: &P2PMessageMetadata,
    payload: &[u8],
) -> Result<message::message_event::Msg, P2PMessageDecodeError> {
    // We first try to decode the network message with rust-bitcoin.
    // If that fails, we try to handle a few known, weird messages.
    match decode_rust_bitcoin_network_message(meta, payload) {
        Ok(rust_bitcoin_network_message) => Ok((&rust_bitcoin_network_message).into()),
        Err(e) => {
            if let Some(message) = decode_weird_network_message(meta, payload) {
                return Ok(message);
            }
            Err(e)
        }
    }
}

fn decode_rust_bitcoin_network_message(
    meta: &P2PMessageMetadata,
    payload: &[u8],
) -> Result<NetworkMessage, P2PMessageDecodeError> {
    let mut raw_message: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for (i, b) in meta.msg_type.iter().enumerate() {
        if *b == 0x00 {
            break;
        }
        raw_message[4 + i] = *b;
    }
    let payload_hash = sha256d::Hash::hash(payload);
    raw_message.append(&mut (meta.msg_size as u32).to_le_bytes().to_vec());
    raw_message.append(&mut payload_hash[..4].to_vec());
    raw_message.append(&mut payload.to_vec());

    match RawNetworkMessage::consensus_decode(&mut raw_message.as_slice()) {
        Ok(rnm) => Ok(rnm.payload().clone()),
        Err(e) => Err(P2PMessageDecodeError::new(meta.clone(), e)),
    }
}

// There might be cases where rust-bitcoin can't deserialize a message.
// This happens, for example, when a message has no elements but rust-bitcoin
// expects at least one element. We try to handle known cases here on a best
// effort basis.
fn decode_weird_network_message(
    meta: &P2PMessageMetadata,
    payload: &[u8],
) -> Option<message::message_event::Msg> {
    match meta.msg_type().as_str() {
        "addrv2" => {
            if meta.msg_size == 0 {
                // case: empty addrv2 message.
                log::debug!("emtpy addrv2: {}", meta);
                return Some(message::message_event::Msg::Emptyaddrv2(true));
            }
        }
        "ping" => {
            if meta.msg_size == 0 {
                // case: old ping message with no nonce.
                log::debug!("no-value ping: {}", meta);
                return Some(message::message_event::Msg::Oldping(true));
            }
        }
        "tx" => {
            log::debug!(
                "invalid (?) tx with {} byte: {}",
                meta.msg_size,
                payload.to_lower_hex_string(),
            );
        }
        _ => (),
    }
    None
}

#[derive(Debug)]
pub struct P2PMessageDecodeError {
    meta: Box<P2PMessageMetadata>,
    error: consensus::encode::Error,
}

impl P2PMessageDecodeError {
    fn new(meta: P2PMessageMetadata, error: consensus::encode::Error) -> Self {
        P2PMessageDecodeError {
            meta: Box::new(meta),
            error,
        }
    }
}

impl fmt::Display for P2PMessageDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "P2P message decode error: {}: {}", self.meta, self.error)
    }
}

#[repr(C)]
pub struct AddrmanInsertNew {
    pub inserted: bool,
    pub bucket: i32,
    pub bucket_pos: i32,
    pub addr: [u8; MAX_PEER_ADDR_LENGTH],
    pub addr_as: u32,
    pub source: [u8; MAX_PEER_ADDR_LENGTH],
    pub source_as: u32,
}

impl AddrmanInsertNew {
    /// Extracts the IP address as a string from the addr bytes.
    pub fn addr(&self) -> String {
        String::from_utf8_lossy(self.addr.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    /// Extracts the source IP address as a string from the source bytes.
    pub fn source(&self) -> String {
        String::from_utf8_lossy(self.source.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    pub fn from_bytes(x: &[u8]) -> AddrmanInsertNew {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const AddrmanInsertNew) }
    }
}

impl fmt::Display for AddrmanInsertNew {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AddrmanInsertNew(inserted={}, bucket={}, bucket_pos={}, addr={}, addr_AS={}, source={}, source_AS={})",
            self.inserted,
            self.bucket,
            self.bucket_pos,
            self.addr(),
            self.addr_as,
            self.source(),
            self.source_as,
        )
    }
}

#[repr(C)]
pub struct AddrmanInsertTried {
    pub bucket: i32,
    pub bucket_pos: i32,
    pub addr: [u8; MAX_PEER_ADDR_LENGTH],
    pub addr_as: u32,
    pub source: [u8; MAX_PEER_ADDR_LENGTH],
    pub source_as: u32,
}

impl AddrmanInsertTried {
    /// Extracts the IP address as a string from the addr bytes.
    pub fn addr(&self) -> String {
        String::from_utf8_lossy(self.addr.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    /// Extracts the source IP address as a string from the source bytes.
    pub fn source(&self) -> String {
        String::from_utf8_lossy(self.source.split(|c| *c == 0x00u8).next().unwrap()).into_owned()
    }

    pub fn from_bytes(x: &[u8]) -> AddrmanInsertTried {
        unsafe { ptr::read_unaligned(x.as_ptr() as *const AddrmanInsertTried) }
    }
}

impl fmt::Display for AddrmanInsertTried {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AddrmanInsertTried(bucket={}, bucket_pos={}, addr={}, addr_AS={}, source={}, source_AS={})",
            self.bucket,
            self.bucket_pos,
            self.addr(),
            self.addr_as,
            self.source(),
            self.source_as,
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn p2p_message_from_bytes_1() {
        // The actual message ends after the "92e4200d3021c21b" payload. It's a few bytes larger
        // on purpose to test that it's still parsed correctly.
        let data_hex = "c79e9300000000003230392e3232322e3235322e34303a36343830390000000069746e6573732076657273696f6e20726573657276656420666f7220736f66742d666f726b20757067726164696e626f756e64005583899738227ad1576a13fc70696e6700000000f5d60e67005930cb080000000000000092e4200d3021c21b649b92000000000033";
        let data = hex::decode(data_hex).unwrap();
        let message = P2PMessage::from_bytes(&data);

        assert_eq!(message.meta.peer_id, 9674439u64);
        assert_eq!(message.meta.peer_addr(), "209.222.252.40:64809");
        assert_eq!(message.meta.peer_conn_type(), "inbound");
        assert_eq!(message.meta.msg_type(), "ping");
        assert_eq!(message.meta.msg_inbound, false);
        assert_eq!(message.meta.msg_size, 8u64);
        assert_eq!(message.payload, hex::decode("92e4200d3021c21b").unwrap());

        message.decode_to_protobuf_network_message().unwrap();
    }

    #[test]
    fn p2p_message_from_bytes_huge() {
        let metadata_hex = "c79e9300000000003230392e3232322e3235322e34303a36343830390000000069746e6573732076657273696f6e20726573657276656420666f7220736f66742d666f726b20757067726164696e626f756e64005583899738227ad1576a13fc70696e6700000000f5d60e67005930cb080000000000000092e4200d3021c21b";
        let metadata = hex::decode(metadata_hex).unwrap();
        let max_len_payload = vec![0; MAX_P2P_MESSAGE_SIZE];

        // In a previous version, this causes a stack overflow. No need to try to
        // decode_to_protobuf_network_message() here as this will fail due to having
        // an all zero payload.
        let _message = P2PMessage::from_bytes(&[metadata, max_len_payload.to_vec()].concat());
    }
}
