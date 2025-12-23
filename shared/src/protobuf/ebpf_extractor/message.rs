use bitcoin::bip152;
use bitcoin::hashes::Hash;
use bitcoin::hex::*;
use bitcoin::p2p;

use std::fmt;

use crate::protobuf::bitcoin_primitives::{Address, BlockHeader, PrefilledTransaction};

// structs are generated via the p2p.proto file
include!(concat!(env!("OUT_DIR"), "/ebpf_extractor.message.rs"));

impl From<bip152::HeaderAndShortIds> for CompactBlock {
    fn from(cmpct_block: bip152::HeaderAndShortIds) -> Self {
        CompactBlock {
            header: BlockHeader::from(cmpct_block.header),
            nonce: cmpct_block.nonce,
            short_ids: cmpct_block
                .short_ids
                .iter()
                .map(|id| id.to_bytes().to_vec())
                .collect(),
            transactions: cmpct_block
                .prefilled_txs
                .iter()
                .map(|tx| PrefilledTransaction::from(tx.clone()))
                .collect(),
        }
    }
}

impl From<bitcoin::Block> for Block {
    fn from(block: bitcoin::Block) -> Self {
        Block {
            header: block.header.into(),
            transactions: block.txdata.iter().map(|tx| tx.clone().into()).collect(),
        }
    }
}

impl From<p2p::message_compact_blocks::SendCmpct> for SendCompact {
    fn from(send_cmpct: p2p::message_compact_blocks::SendCmpct) -> Self {
        SendCompact {
            send_compact: send_cmpct.send_compact,
            version: send_cmpct.version,
        }
    }
}

impl From<p2p::message_filter::GetCFCheckpt> for GetCfCheckpt {
    fn from(getcfcheckpt: p2p::message_filter::GetCFCheckpt) -> Self {
        GetCfCheckpt {
            filter_type: getcfcheckpt.filter_type as u32,
            stop_hash: getcfcheckpt.stop_hash.as_byte_array().to_vec(),
        }
    }
}

impl From<p2p::message_filter::CFCheckpt> for CfCheckpt {
    fn from(cfcheckpt: p2p::message_filter::CFCheckpt) -> Self {
        CfCheckpt {
            filter_type: cfcheckpt.filter_type as u32,
            stop_hash: cfcheckpt.stop_hash.as_byte_array().to_vec(),
            filter_headers: cfcheckpt
                .filter_headers
                .iter()
                .map(|h| h.as_byte_array().to_vec())
                .collect(),
        }
    }
}

impl From<p2p::message_filter::CFHeaders> for CfHeaders {
    fn from(cfheaders: p2p::message_filter::CFHeaders) -> Self {
        CfHeaders {
            filter_type: cfheaders.filter_type as u32,
            stop_hash: cfheaders.stop_hash.as_byte_array().to_vec(),
            previous_filter_header: cfheaders.previous_filter_header.as_byte_array().to_vec(),
            filter_hashes: cfheaders
                .filter_hashes
                .iter()
                .map(|h| h.as_byte_array().to_vec())
                .collect(),
        }
    }
}

impl From<p2p::message_filter::GetCFilters> for GetCFilter {
    fn from(getcfilter: p2p::message_filter::GetCFilters) -> Self {
        GetCFilter {
            filter_type: getcfilter.filter_type as u32,
            start_height: getcfilter.start_height,
            stop_hash: getcfilter.stop_hash.as_byte_array().to_vec(),
        }
    }
}

impl From<p2p::message_filter::GetCFHeaders> for GetCfHeaders {
    fn from(getcfheaders: p2p::message_filter::GetCFHeaders) -> Self {
        GetCfHeaders {
            filter_type: getcfheaders.filter_type as u32,
            start_height: getcfheaders.start_height,
            stop_hash: getcfheaders.stop_hash.as_byte_array().to_vec(),
        }
    }
}

impl From<p2p::message_filter::CFilter> for CFilter {
    fn from(cfilter: p2p::message_filter::CFilter) -> Self {
        CFilter {
            filter_type: cfilter.filter_type as u32,
            block_hash: cfilter.block_hash.as_byte_array().to_vec(),
            filter: cfilter.filter.to_vec(),
        }
    }
}

impl From<bitcoin::MerkleBlock> for MerkleBlock {
    fn from(merkle_block: bitcoin::MerkleBlock) -> Self {
        MerkleBlock {
            header: merkle_block.header.into(),
            num_transactions: merkle_block.txn.num_transactions(),
            bits: merkle_block.txn.bits().to_vec(),
            hashes: merkle_block
                .txn
                .hashes()
                .iter()
                .map(|h| h.as_byte_array().to_vec())
                .collect(),
        }
    }
}

impl From<bitcoin::Transaction> for Tx {
    fn from(tx: bitcoin::Transaction) -> Self {
        Tx { tx: tx.into() }
    }
}

impl From<bip152::BlockTransactionsRequest> for GetBlockTxn {
    fn from(request: bip152::BlockTransactionsRequest) -> Self {
        GetBlockTxn {
            block_hash: request.block_hash.as_byte_array().to_vec(),
            tx_indexes: request.indexes,
        }
    }
}

impl From<bip152::BlockTransactions> for BlockTxn {
    fn from(blocktxn: bip152::BlockTransactions) -> Self {
        BlockTxn {
            block_hash: blocktxn.block_hash.as_byte_array().to_vec(),
            transactions: blocktxn
                .transactions
                .iter()
                .map(|tx| tx.clone().into())
                .collect(),
        }
    }
}

impl From<p2p::message_bloom::FilterLoad> for FilterLoad {
    fn from(filterload: p2p::message_bloom::FilterLoad) -> Self {
        FilterLoad {
            filter: filterload.filter.to_vec(),
            hash_funcs: filterload.hash_funcs,
            tweak: filterload.tweak,
            flags: match filterload.flags {
                p2p::message_bloom::BloomFlags::None => filter_load::BloomFlags::None as i32,
                p2p::message_bloom::BloomFlags::All => filter_load::BloomFlags::All as i32,
                p2p::message_bloom::BloomFlags::PubkeyOnly => {
                    filter_load::BloomFlags::PubkeyOnly as i32
                }
            },
        }
    }
}

impl From<p2p::message_network::Reject> for Reject {
    fn from(reject: p2p::message_network::Reject) -> Self {
        Reject {
            rejected_command: reject.message.to_string(),
            reason: match reject.ccode {
                p2p::message_network::RejectReason::Malformed => {
                    reject::RejectReason::Malformed as i32
                }
                p2p::message_network::RejectReason::Invalid => reject::RejectReason::Invalid as i32,
                p2p::message_network::RejectReason::Obsolete => {
                    reject::RejectReason::Obsolete as i32
                }
                p2p::message_network::RejectReason::Duplicate => {
                    reject::RejectReason::Duplicate as i32
                }
                p2p::message_network::RejectReason::NonStandard => {
                    reject::RejectReason::Nonstandard as i32
                }
                p2p::message_network::RejectReason::Dust => reject::RejectReason::Dust as i32,
                p2p::message_network::RejectReason::Fee => reject::RejectReason::Fee as i32,
                p2p::message_network::RejectReason::Checkpoint => {
                    reject::RejectReason::Checkpoint as i32
                }
            },
            reason_details: reject.reason.clone().into(),
            hash: reject.hash.as_byte_array().to_vec(),
        }
    }
}

impl From<p2p::message_network::VersionMessage> for Version {
    fn from(version_msg: p2p::message_network::VersionMessage) -> Self {
        Version {
            version: version_msg.version,
            services: version_msg.services.to_u64(),
            timestamp: version_msg.timestamp,
            receiver: Address {
                timestamp: 0,
                port: version_msg.receiver.port as u32,
                services: version_msg.receiver.services.to_u64(),
                address: Some(version_msg.receiver.into()),
            },
            sender: Address {
                timestamp: 0,
                port: version_msg.sender.port as u32,
                services: version_msg.sender.services.to_u64(),
                address: Some(version_msg.sender.into()),
            },
            nonce: version_msg.nonce,
            user_agent: version_msg.user_agent.clone(),
            start_height: version_msg.start_height,
            relay: version_msg.relay,
        }
    }
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ping({})", self.value)
    }
}

impl fmt::Display for Pong {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pong({})", self.value)
    }
}

impl fmt::Display for Inv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let item_strs: Vec<String> = self.items.iter().map(|i| i.to_string()).collect();
        write!(f, "Inv([{}])", item_strs.join(", "))
    }
}

impl fmt::Display for GetData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let item_strs: Vec<String> = self.items.iter().map(|i| i.to_string()).collect();
        write!(f, "GetData([{}])", item_strs.join(", "))
    }
}

impl fmt::Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let item_strs: Vec<String> = self.items.iter().map(|i| i.to_string()).collect();
        write!(f, "NotFound([{}])", item_strs.join(", "))
    }
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Tx({})", self.tx)
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let header_strings: Vec<String> = self.headers.iter().map(|i| i.to_string()).collect();
        write!(f, "Headers([{}])", header_strings.join(", "))
    }
}

impl fmt::Display for GetHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hashes_strs: Vec<String> = self
            .locator_hashes
            .iter()
            .map(|h| bitcoin::BlockHash::from_slice(h).unwrap().to_string())
            .collect();
        write!(
            f,
            "GetHeaders(version={}, locator_hashes=[{}], stop_hash={})",
            self.version,
            hashes_strs.join(", "),
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap()
        )
    }
}

impl fmt::Display for GetBlocks {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hashes_strs: Vec<String> = self
            .locator_hashes
            .iter()
            .map(|h| bitcoin::BlockHash::from_slice(h).unwrap().to_string())
            .collect();
        write!(
            f,
            "GetBlocks(version={}, locator_hashes=[{}], stop_hash={})",
            self.version,
            hashes_strs.join(", "),
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap()
        )
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr_strings: Vec<String> = self.addresses.iter().map(|i| i.to_string()).collect();
        write!(f, "Addr([{}])", addr_strings.join(", "))
    }
}

impl fmt::Display for AddrV2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addr_strings: Vec<String> = self.addresses.iter().map(|i| i.to_string()).collect();
        write!(f, "AddrV2([{}])", addr_strings.join(", "))
    }
}

impl fmt::Display for FeeFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FeeFilter({})", self.fee)
    }
}

impl fmt::Display for reject::RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            reject::RejectReason::Malformed => write!(f, "Malformed"),
            reject::RejectReason::Invalid => write!(f, "Invalid"),
            reject::RejectReason::Obsolete => write!(f, "Obsolete"),
            reject::RejectReason::Duplicate => write!(f, "Duplicate"),
            reject::RejectReason::Nonstandard => write!(f, "NonStandard"),
            reject::RejectReason::Fee => write!(f, "Fee"),
            reject::RejectReason::Dust => write!(f, "Dust"),
            reject::RejectReason::Checkpoint => write!(f, "Checkpoint"),
        }
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Reject(command={}, reason={}, details={}, hash={})",
            self.rejected_command,
            self.reason,
            self.reason_details,
            bitcoin::BlockHash::from_slice(&self.hash).unwrap()
        )
    }
}

impl fmt::Display for SendCompact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SendCompact(send_compact={}, version={})",
            self.send_compact, self.version
        )
    }
}

impl fmt::Display for CompactBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let short_id_strs: Vec<String> = self
            .short_ids
            .iter()
            .map(|id| id.to_lower_hex_string())
            .collect();
        let ptx_strs: Vec<String> = self.transactions.iter().map(|pt| pt.to_string()).collect();
        write!(
            f,
            "CmpctBlock(header={}, nonce={}, short_ids=[{}], prefilled_transactions=[{}])",
            self.header,
            self.nonce,
            short_id_strs.join(", "),
            ptx_strs.join(", ")
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tx_strs: Vec<String> = self.transactions.iter().map(|tx| tx.to_string()).collect();
        write!(
            f,
            "Block(header={}, transactions={})",
            self.header,
            tx_strs.join(", ")
        )
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Metadata(peer_id={}, addr={}, conn_type={}, command={}, inbound={}, size={})",
            self.peer_id, self.addr, self.conn_type, self.command, self.inbound, self.size
        )
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Version(version={}, services={}, timestamp={}, receiver={}, sender={}, nonce={}, user_agent={}, start_height={}, relay={})", self.version, self.services, self.timestamp, self.receiver, self.sender, self.nonce, self.user_agent, self.start_height, self.relay)
    }
}

impl fmt::Display for GetBlockTxn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let index_strs: Vec<String> = self.tx_indexes.iter().map(|i| i.to_string()).collect();
        write!(
            f,
            "GetBlockTxn(hash={}, tx_indexes={})",
            bitcoin::BlockHash::from_slice(&self.block_hash).unwrap(),
            index_strs.join(", ")
        )
    }
}

impl fmt::Display for BlockTxn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tx_strs: Vec<String> = self.transactions.iter().map(|tx| tx.to_string()).collect();
        write!(
            f,
            "BlockTxn(hash={}, transactions={})",
            bitcoin::BlockHash::from_slice(&self.block_hash).unwrap(),
            tx_strs.join(", ")
        )
    }
}

impl fmt::Display for Alert {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Alert(alert={})", self.alert.to_lower_hex_string(),)
    }
}

impl fmt::Display for FilterAdd {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FilterAdd(filter={})", self.filter.to_lower_hex_string(),)
    }
}

impl fmt::Display for filter_load::BloomFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            filter_load::BloomFlags::None => write!(f, "None"),
            filter_load::BloomFlags::All => write!(f, "All"),
            filter_load::BloomFlags::PubkeyOnly => write!(f, "PubkeyOnly"),
        }
    }
}

impl fmt::Display for GetCfCheckpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "GetCFCheckpt(filter_type={}, stop_hash={})",
            self.filter_type,
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap(),
        )
    }
}

impl fmt::Display for GetCfHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "GetCFHeaders(filter_type={}, start_height={}, stop_hash={})",
            self.filter_type,
            self.start_height,
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap(),
        )
    }
}

impl fmt::Display for GetCFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "GetCFilter(filter_type={}, start_height={}, stop_hash={})",
            self.filter_type,
            self.start_height,
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap(),
        )
    }
}

impl fmt::Display for CFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CFilter(filter_type={}, block_hash={}, filter={})",
            self.filter_type,
            bitcoin::BlockHash::from_slice(&self.block_hash).unwrap(),
            self.filter.to_lower_hex_string(),
        )
    }
}

impl fmt::Display for CfHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let filter_hash_strs: Vec<String> = self
            .filter_hashes
            .iter()
            .map(|h| {
                bitcoin::hash_types::FilterHash::from_slice(h)
                    .unwrap()
                    .to_string()
            })
            .collect();
        write!(
            f,
            "CFHeaders(filter_type={}, stop_hash={}, prev_filter_header={}, filter_hashes=[{}])",
            self.filter_type,
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap(),
            bitcoin::hash_types::FilterHeader::from_slice(&self.previous_filter_header).unwrap(),
            filter_hash_strs.join(", "),
        )
    }
}

impl fmt::Display for CfCheckpt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let filter_header_strs: Vec<String> = self
            .filter_headers
            .iter()
            .map(|h| {
                bitcoin::hash_types::FilterHeader::from_slice(h)
                    .unwrap()
                    .to_string()
            })
            .collect();
        write!(
            f,
            "CFCheckpt(filter_type={}, stop_hash={}, filter_headers=[{}])",
            self.filter_type,
            bitcoin::BlockHash::from_slice(&self.stop_hash).unwrap(),
            filter_header_strs.join(", "),
        )
    }
}

impl fmt::Display for FilterLoad {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FilterLoad(filter={}, hash_funcs={}, tweak={}, flags={})",
            self.filter.to_lower_hex_string(),
            self.hash_funcs,
            self.tweak,
            self.flags
        )
    }
}

impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FilterLoad(command={}, payload={})",
            self.command,
            self.payload.to_lower_hex_string(),
        )
    }
}

impl fmt::Display for MerkleBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bits_strs: Vec<String> = self.bits.iter().map(|b| b.to_string()).collect();
        let hash_strs: Vec<String> = self
            .hashes
            .iter()
            .map(|h| {
                bitcoin::hash_types::TxMerkleNode::from_slice(h)
                    .unwrap()
                    .to_string()
            })
            .collect();
        write!(
            f,
            "MerkleBlock(header={}, num_transactions={}, bits=[{}], hashes=[{}])",
            self.header,
            self.num_transactions,
            bits_strs.join(","),
            hash_strs.join(", "),
        )
    }
}

impl fmt::Display for message_event::Msg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            message_event::Msg::Ping(ping) => write!(f, "{}", ping),
            message_event::Msg::Pong(pong) => write!(f, "{}", pong),
            message_event::Msg::Inv(inv) => write!(f, "{}", inv),
            message_event::Msg::Getdata(getdata) => write!(f, "{}", getdata),
            message_event::Msg::Tx(tx) => write!(f, "{}", tx),
            message_event::Msg::Headers(headers) => write!(f, "{}", headers),
            message_event::Msg::Addr(addr) => write!(f, "{}", addr),
            message_event::Msg::Addrv2(addr) => write!(f, "{}", addr),
            message_event::Msg::Feefilter(feefilter) => write!(f, "{}", feefilter),
            message_event::Msg::Getheaders(getheaders) => write!(f, "{}", getheaders),
            message_event::Msg::Getblocks(getblocks) => write!(f, "{}", getblocks),
            message_event::Msg::Version(version) => write!(f, "{}", version),
            message_event::Msg::Notfound(notfound) => write!(f, "{}", notfound),
            message_event::Msg::Reject(reject) => write!(f, "{}", reject),
            message_event::Msg::Compactblock(compactblock) => write!(f, "{}", compactblock),
            message_event::Msg::Sendcompact(sendcompact) => write!(f, "{}", sendcompact),
            message_event::Msg::Block(block) => write!(f, "{}", block),
            message_event::Msg::Getblocktxn(getblocktxn) => write!(f, "{}", getblocktxn),
            message_event::Msg::Blocktxn(blocktxn) => write!(f, "{}", blocktxn),
            message_event::Msg::Alert(blocktxn) => write!(f, "{}", blocktxn),
            message_event::Msg::Filteradd(filteradd) => write!(f, "{}", filteradd),
            message_event::Msg::Filterload(filterload) => write!(f, "{}", filterload),
            message_event::Msg::Getcfcheckpt(getcfcheckpt) => write!(f, "{}", getcfcheckpt),
            message_event::Msg::Cfcheckpt(cfcheckpt) => write!(f, "{}", cfcheckpt),
            message_event::Msg::Cfheaders(cfheaders) => write!(f, "{}", cfheaders),
            message_event::Msg::Getcfheaders(getcfheaders) => write!(f, "{}", getcfheaders),
            message_event::Msg::Getcfilter(getcfilter) => write!(f, "{}", getcfilter),
            message_event::Msg::Cfilter(cfilter) => write!(f, "{}", cfilter),
            message_event::Msg::Merkleblock(merkleblock) => write!(f, "{}", merkleblock),
            message_event::Msg::Unknown(unknown) => write!(f, "{}", unknown),
            message_event::Msg::Filterclear(_) => write!(f, "filterclear"),
            message_event::Msg::Verack(_) => write!(f, "verack"),
            message_event::Msg::Sendheaders(_) => write!(f, "sendHeaders"),
            message_event::Msg::Getaddr(_) => write!(f, "getaddr"),
            message_event::Msg::Mempool(_) => write!(f, "mempool"),
            message_event::Msg::Wtxidrelay(_) => write!(f, "wtxidrelay"),
            message_event::Msg::Sendaddrv2(_) => write!(f, "sendaddrv2"),
            message_event::Msg::Emptyaddrv2(_) => write!(f, "empty_addrv2"),
            message_event::Msg::Oldping(_) => write!(f, "old_ping"),
        }
    }
}

impl fmt::Display for MessageEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.msg {
            Some(msg) => write!(
                f,
                "{} id={} (conn_type={}): {}",
                if self.meta.inbound {
                    "inbound from"
                } else {
                    "outbound to"
                },
                self.meta.peer_id,
                self.meta.conn_type,
                msg
            ),
            None => write!(f, "Message(meta={}, msg=None)", self.meta),
        }
    }
}

impl From<&p2p::message::NetworkMessage> for message_event::Msg {
    fn from(msg: &p2p::message::NetworkMessage) -> Self {
        use bitcoin::p2p::message::NetworkMessage;
        use message_event::Msg;

        match msg {
            NetworkMessage::Ping(x) => Msg::Ping(Ping { value: *x }),
            NetworkMessage::Pong(x) => Msg::Pong(Pong { value: *x }),
            NetworkMessage::Inv(invs) => Msg::Inv(Inv {
                items: invs.iter().map(|inv| (*inv).into()).collect(),
            }),
            NetworkMessage::NotFound(invs) => Msg::Notfound(NotFound {
                items: invs.iter().map(|inv| (*inv).into()).collect(),
            }),
            NetworkMessage::Tx(tx) => Msg::Tx(tx.clone().into()),
            NetworkMessage::GetData(gets) => Msg::Getdata(GetData {
                items: gets.iter().map(|get| (*get).into()).collect(),
            }),
            NetworkMessage::Headers(headers) => Msg::Headers(Headers {
                headers: headers.iter().map(|h| (*h).into()).collect(),
            }),
            NetworkMessage::Addr(addrs) => Msg::Addr(Addr {
                addresses: addrs
                    .iter()
                    .map(|addr_entry| addr_entry.clone().into())
                    .collect(),
            }),
            NetworkMessage::AddrV2(addrs) => Msg::Addrv2(AddrV2 {
                addresses: addrs.iter().map(|addrv2| addrv2.clone().into()).collect(),
            }),
            NetworkMessage::FeeFilter(fee) => Msg::Feefilter(FeeFilter { fee: *fee }),
            NetworkMessage::GetHeaders(get_headers_msg) => Msg::Getheaders(GetHeaders {
                version: get_headers_msg.version,
                locator_hashes: get_headers_msg
                    .locator_hashes
                    .iter()
                    .map(|h| h.as_byte_array().to_vec())
                    .collect(),
                stop_hash: get_headers_msg.stop_hash.as_byte_array().to_vec(),
            }),
            NetworkMessage::GetBlocks(get_blocks_msg) => Msg::Getblocks(GetBlocks {
                version: get_blocks_msg.version,
                locator_hashes: get_blocks_msg
                    .locator_hashes
                    .iter()
                    .map(|h| h.as_byte_array().to_vec())
                    .collect(),
                stop_hash: get_blocks_msg.stop_hash.as_byte_array().to_vec(),
            }),
            NetworkMessage::WtxidRelay => Msg::Wtxidrelay(true),
            NetworkMessage::SendAddrV2 => Msg::Sendaddrv2(true),
            NetworkMessage::Verack => Msg::Verack(true),
            NetworkMessage::SendHeaders => Msg::Sendheaders(true),
            NetworkMessage::GetAddr => Msg::Getaddr(true),
            NetworkMessage::MemPool => Msg::Mempool(true),
            NetworkMessage::Reject(reject) => Msg::Reject(reject.clone().into()),
            NetworkMessage::Version(version) => Msg::Version(version.clone().into()),
            NetworkMessage::CmpctBlock(cmpct_block) => {
                Msg::Compactblock(cmpct_block.compact_block.clone().into())
            }
            NetworkMessage::SendCmpct(send_cmpct) => Msg::Sendcompact((*send_cmpct).into()),
            NetworkMessage::Block(block) => Msg::Block(block.clone().into()),
            NetworkMessage::GetBlockTxn(request) => {
                Msg::Getblocktxn(request.txs_request.clone().into())
            }
            NetworkMessage::BlockTxn(response) => {
                Msg::Blocktxn(response.transactions.clone().into())
            }
            NetworkMessage::Alert(alert) => Msg::Alert(Alert {
                alert: alert.clone(),
            }),
            NetworkMessage::FilterAdd(filteradd) => Msg::Filteradd(FilterAdd {
                filter: filteradd.data.clone(),
            }),
            NetworkMessage::FilterClear => Msg::Filterclear(true),
            NetworkMessage::FilterLoad(filterload) => Msg::Filterload(filterload.clone().into()),
            NetworkMessage::GetCFCheckpt(getcfcheckpt) => {
                Msg::Getcfcheckpt(getcfcheckpt.clone().into())
            }
            NetworkMessage::CFCheckpt(cfcheckpt) => Msg::Cfcheckpt(cfcheckpt.clone().into()),
            NetworkMessage::GetCFHeaders(getcfheaders) => {
                Msg::Getcfheaders(getcfheaders.clone().into())
            }
            NetworkMessage::CFHeaders(cfheaders) => Msg::Cfheaders(cfheaders.clone().into()),
            NetworkMessage::GetCFilters(getcfilter) => Msg::Getcfilter(getcfilter.clone().into()),
            NetworkMessage::CFilter(cfilter) => Msg::Cfilter(cfilter.clone().into()),
            NetworkMessage::MerkleBlock(merkle_block) => {
                Msg::Merkleblock(merkle_block.clone().into())
            }
            NetworkMessage::Unknown { command, payload } => Msg::Unknown(Unknown {
                command: command.to_string(),
                payload: payload.to_vec(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {}
