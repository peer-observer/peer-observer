use base32;

use bitcoin::bip152;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::p2p;

use std::fmt;
use std::net::SocketAddr;

// structs are generated via the p2p.proto file
include!(concat!(env!("OUT_DIR"), "/bitcoin_primitives.rs"));

impl From<bitcoin::block::Header> for BlockHeader {
    fn from(header: bitcoin::block::Header) -> Self {
        BlockHeader {
            hash: header.block_hash().as_byte_array().to_vec(),
            version: header.version.to_consensus(),
            prev_blockhash: header.prev_blockhash.as_byte_array().to_vec(),
            merkle_root: header.merkle_root.as_byte_array().to_vec(),
            time: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
        }
    }
}

impl From<bip152::PrefilledTransaction> for PrefilledTransaction {
    fn from(prefilled_tx: bip152::PrefilledTransaction) -> Self {
        PrefilledTransaction {
            diff_index: prefilled_tx.idx as u32,
            tx: prefilled_tx.tx.into(),
        }
    }
}

impl From<p2p::address::Address> for address::Address {
    fn from(addr: p2p::address::Address) -> Self {
        match addr.socket_addr() {
            Ok(x) => {
                // is either an IPv4 or IPv6 address
                match x {
                    SocketAddr::V4(a) => address::Address::Ipv4(a.ip().to_string()),
                    SocketAddr::V6(a) => address::Address::Ipv6(a.ip().to_string()),
                }
            }
            Err(_) => {
                let mut addr_vec = vec![];
                for (i, x) in addr.address.iter().enumerate() {
                    // The first three u16's, contain an onion prefix, are skipped here.
                    if i >= 3 {
                        addr_vec.push((*x >> 8) as u8);
                        addr_vec.push(*x as u8);
                    }
                }
                address::Address::Torv2(format!(
                    "{}.onion",
                    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &addr_vec)
                        .to_lowercase()
                ))
            }
        }
    }
}

impl From<(u32, p2p::address::Address)> for Address {
    fn from(addr_entry: (u32, p2p::address::Address)) -> Self {
        Address {
            timestamp: addr_entry.0,
            services: addr_entry.1.services.to_u64(),
            port: addr_entry.1.port as u32,
            address: Some(addr_entry.1.clone().into()),
        }
    }
}

impl From<p2p::address::AddrV2Message> for Address {
    fn from(addrv2: p2p::address::AddrV2Message) -> Self {
        Address {
            timestamp: addrv2.time,
            services: addrv2.services.to_u64(),
            port: addrv2.port as u32,
            address: Some(addrv2.addr.into()),
        }
    }
}

impl From<p2p::address::AddrV2> for address::Address {
    fn from(addr: p2p::address::AddrV2) -> Self {
        match addr {
            p2p::address::AddrV2::Ipv4(a) => address::Address::Ipv4(a.to_string()),
            p2p::address::AddrV2::Ipv6(a) => address::Address::Ipv6(a.to_string()),
            p2p::address::AddrV2::TorV2(a) => address::Address::Torv2(format!(
                "{}.onion",
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &a).to_lowercase()
            )),
            p2p::address::AddrV2::TorV3(a) => address::Address::Torv3(format!(
                "{}.onion",
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &a).to_lowercase()
            )),
            p2p::address::AddrV2::I2p(a) => address::Address::I2p(format!(
                "{}.b32.i2p",
                base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &a).to_lowercase()
            )),
            p2p::address::AddrV2::Cjdns(a) => address::Address::Cjdns(a.to_string()),
            p2p::address::AddrV2::Unknown(id, a) => address::Address::Unknown(UnknownAddress {
                id: id as u32,
                address: a.to_vec(),
            }),
        }
    }
}

impl fmt::Display for PrefilledTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PrefilledTransaction(diff_index={}, tx={})",
            self.diff_index, self.tx,
        )
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction(txid={}, wtxid={})",
            bitcoin::Txid::from_slice(&self.txid).unwrap(),
            bitcoin::Wtxid::from_slice(&self.wtxid).unwrap()
        )
    }
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BlockHeader(hash={}, version={}, prev_blockhash={}, merkle_root={}, time={}, bits={}, nonce={})",
            bitcoin::BlockHash::from_slice(&self.hash).unwrap(),
            self.version,
            bitcoin::BlockHash::from_slice(&self.prev_blockhash).unwrap(),
            bitcoin::TxMerkleNode::from_slice(&self.merkle_root).unwrap(),
            self.time,
            self.bits,
            self.nonce,
        )
    }
}

impl From<bitcoin::Transaction> for Transaction {
    fn from(tx: bitcoin::Transaction) -> Self {
        Transaction {
            txid: tx.compute_txid().as_byte_array().to_vec(),
            wtxid: tx.compute_wtxid().as_byte_array().to_vec(),
            raw: Some(bitcoin::consensus::serialize(&tx)),
        }
    }
}

impl From<String> for ConnType {
    fn from(conntype: String) -> Self {
        match conntype.as_str() {
            "inbound" => ConnType::Inbound,
            "outbound-full-relay" => ConnType::OutboundFullRelay,
            "block-relay-only" => ConnType::BlockRelayOnly,
            "feeler" => ConnType::OutboundFullRelay,
            _ => ConnType::Unknown,
        }
    }
}

impl From<p2p::message_blockdata::Inventory> for InventoryItem {
    fn from(inv_item: p2p::message_blockdata::Inventory) -> Self {
        use p2p::message_blockdata::Inventory;
        match inv_item {
            Inventory::Error => InventoryItem {
                item: Some(inventory_item::Item::Error(true)),
            },
            Inventory::Transaction(txid) => InventoryItem {
                item: Some(inventory_item::Item::Transaction(
                    txid.as_byte_array().to_vec(),
                )),
            },
            Inventory::Block(hash) => InventoryItem {
                item: Some(inventory_item::Item::Block(hash.as_byte_array().to_vec())),
            },
            Inventory::WTx(wtxid) => InventoryItem {
                item: Some(inventory_item::Item::Wtx(wtxid.as_byte_array().to_vec())),
            },
            Inventory::WitnessTransaction(txid) => InventoryItem {
                item: Some(inventory_item::Item::WitnessTransaction(
                    txid.as_byte_array().to_vec(),
                )),
            },
            Inventory::WitnessBlock(hash) => InventoryItem {
                item: Some(inventory_item::Item::WitnessBlock(
                    hash.as_byte_array().to_vec(),
                )),
            },
            Inventory::CompactBlock(hash) => InventoryItem {
                item: Some(inventory_item::Item::CompactBlock(
                    hash.as_byte_array().to_vec(),
                )),
            },
            Inventory::Unknown { inv_type, hash } => InventoryItem {
                item: Some(inventory_item::Item::Unknown(UnknownItem {
                    inv_type,
                    hash: hash.to_vec(),
                })),
            },
        }
    }
}

impl InventoryItem {
    pub fn inv_type(&self) -> &str {
        use inventory_item::Item;
        if let Some(item) = &self.item {
            match item {
                Item::Transaction(_) => "Tx",
                Item::Block(_) => "Block",
                Item::Wtx(_) => "WTx",
                Item::WitnessTransaction(_) => "WitnessTx",
                Item::WitnessBlock(_) => "WitnessBlock",
                Item::CompactBlock(_) => "CompactBlock",
                Item::Unknown(_) => "Unknown",
                Item::Error(_) => "Error",
            }
        } else {
            "None"
        }
    }
}

impl fmt::Display for InventoryItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use inventory_item::Item;
        if let Some(item) = &self.item {
            match item {
                Item::Transaction(txid) => {
                    write!(f, "Tx({})", bitcoin::Txid::from_slice(txid).unwrap())
                }
                Item::Block(hash) => write!(
                    f,
                    "Block({})",
                    bitcoin::BlockHash::from_slice(hash).unwrap()
                ),
                Item::Wtx(wtxid) => {
                    write!(f, "WTx({})", bitcoin::Wtxid::from_slice(wtxid).unwrap())
                }
                Item::WitnessTransaction(wtxid) => {
                    write!(
                        f,
                        "WitnessTx({})",
                        bitcoin::Wtxid::from_slice(wtxid).unwrap()
                    )
                }
                Item::WitnessBlock(hash) => {
                    write!(
                        f,
                        "WitnessBlock({})",
                        bitcoin::BlockHash::from_slice(hash).unwrap()
                    )
                }
                Item::CompactBlock(hash) => {
                    write!(
                        f,
                        "CompactBlock({})",
                        bitcoin::BlockHash::from_slice(hash).unwrap()
                    )
                }
                Item::Unknown(uitem) => write!(
                    f,
                    "Unknown(type={}, hash={})",
                    uitem.inv_type,
                    bitcoin::hashes::sha256::Hash::from_slice(&uitem.hash).unwrap()
                ),
                Item::Error(_) => write!(f, "Error"),
            }
        } else {
            write!(f, "None")
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Address(timestamp={}, address={}, port={}, services={})",
            self.timestamp,
            self.address.as_ref().unwrap(),
            self.port,
            self.services,
        )
    }
}

impl fmt::Display for address::Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            address::Address::Ipv4(a) => write!(f, "IPv4({})", a),
            address::Address::Ipv6(a) => write!(f, "IPv6({})", a),
            address::Address::Torv2(a) => write!(f, "TorV2({})", a),
            address::Address::Torv3(a) => write!(f, "TorV3({})", a),
            address::Address::I2p(a) => write!(f, "I2p({})", a),
            address::Address::Cjdns(a) => write!(f, "Cjdns({})", a),
            address::Address::Unknown(u) => write!(f, "Unknown({})", u),
        }
    }
}

impl address::Address {
    pub fn network(&self) -> &str {
        match self {
            address::Address::Ipv4(_) => "IPv4",
            address::Address::Ipv6(_) => "IPv6",
            address::Address::Torv2(_) => "TorV2",
            address::Address::Torv3(_) => "TorV3",
            address::Address::I2p(_) => "I2P",
            address::Address::Cjdns(_) => "CJDNS",
            address::Address::Unknown(_) => "Unknown",
        }
    }

    /// Returns the address without the the network wrapper. E.g without IPv4(..).
    pub fn inner(&self) -> String {
        match self {
            address::Address::Ipv4(x) => x.to_string(),
            address::Address::Ipv6(x) => x.to_string(),
            address::Address::Torv2(x) => x.to_string(),
            address::Address::Torv3(x) => x.to_string(),
            address::Address::I2p(x) => x.to_string(),
            address::Address::Cjdns(x) => x.to_string(),
            address::Address::Unknown(x) => format!("{}", x),
        }
    }
}

impl fmt::Display for UnknownAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "id={}, bytes={}",
            self.id,
            self.address.to_lower_hex_string()
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_address_into_addrtype_onion() {
        use crate::protobuf::bitcoin_primitives;
        use bitcoin::p2p::address::Address;
        use bitcoin::p2p::ServiceFlags;

        let a = Address {
            services: ServiceFlags::from(0),
            // From
            // https://github.com/bitcoin/bitcoin/pull/1174/commits/70f7f0038592a28e846f02d084f0119fc34eb52f#diff-1d804b435c22c29ffc21022ad3a88a8b7d3bd44ae451c3d50e4700344ffef60dR93-R100
            address: [
                0xFD87, 0xD87E, 0xEB43, 0xedb1, 0x8e4, 0x3588, 0xe546, 0x35ca,
            ],
            port: 0,
        };
        assert_eq!(
            bitcoin_primitives::address::Address::from(a),
            bitcoin_primitives::address::Address::Torv2(String::from("5wyqrzbvrdsumnok.onion"))
        );
    }
}
