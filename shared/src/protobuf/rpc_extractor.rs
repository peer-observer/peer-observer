use corepc_client::types::v17::{
    GetMemoryInfoStats as RPCGetMemoryInfoStats, GetNetTotals as RPCGetNetTotals,
    UploadTarget as RPCUploadTarget,
};
use corepc_client::types::v26::{
    AddrManInfoNetwork as RPCAddrManInfoNetwork, GetAddrManInfo as RPCGetAddrManInfo,
    GetMempoolInfo, GetPeerInfo as RPCGetPeerInfo, PeerInfo as RPCPeerInfo,
};
use corepc_node::vtype::{
    GetBlockchainInfo as RPCGetBlockchainInfo, GetNetworkInfo as RPCGetNetworkInfo,
    GetNetworkInfoAddress as RPCGetNetworkInfoAddress,
    GetNetworkInfoNetwork as RPCGetNetworkInfoNetwork,
};
use std::fmt;

// structs are generated via the rpc_extractor.proto file
include!(concat!(env!("OUT_DIR"), "/rpc_extractor.rs"));

impl fmt::Display for PeerInfos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let info_strs: Vec<String> = self.infos.iter().map(|i| i.to_string()).collect();
        write!(f, "PeerInfos([{}])", info_strs.join(", "))
    }
}

impl From<RPCGetPeerInfo> for PeerInfos {
    fn from(infos: RPCGetPeerInfo) -> Self {
        PeerInfos {
            infos: infos.0.iter().map(|i| i.clone().into()).collect(),
        }
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PeerInfo(id={})", self.id,)
    }
}

impl fmt::Display for rpc::RpcEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            rpc::RpcEvent::PeerInfos(infos) => write!(f, "{}", infos),
            rpc::RpcEvent::MempoolInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::Uptime(seconds) => write!(f, "Uptime({}s)", seconds),
            rpc::RpcEvent::NetTotals(totals) => write!(f, "{}", totals),
            rpc::RpcEvent::MemoryInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::AddrmanInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::NetworkInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::BlockchainInfo(info) => write!(f, "{}", info),
        }
    }
}

impl From<RPCPeerInfo> for PeerInfo {
    fn from(info: RPCPeerInfo) -> Self {
        PeerInfo {
            address: info.address,
            address_bind: info.address_bind.unwrap_or_default(),
            address_local: info.address_local.unwrap_or_default(),
            addr_rate_limited: info.addresses_rate_limited.unwrap_or_default() as u64,
            addr_relay_enabled: info.addresses_relay_enabled.unwrap_or_default(),
            addr_processed: info.addresses_processed.unwrap_or_default() as u64,
            bip152_hb_from: info.bip152_hb_from,
            bip152_hb_to: info.bip152_hb_to,
            bytes_received: info.bytes_received,
            bytes_received_per_message: info.bytes_received_per_message.into_iter().collect(),
            bytes_sent: info.bytes_sent,
            bytes_sent_per_message: info.bytes_sent_per_message.into_iter().collect(),
            connection_time: info.connection_time,
            connection_type: info.connection_type.unwrap_or_default(),
            id: info.id,
            inbound: info.inbound,
            inflight: info.inflight.unwrap_or_default(),
            last_block: info.last_block,
            last_received: info.last_received,
            last_send: info.last_send,
            last_transaction: info.last_transaction,
            mapped_as: info.mapped_as.unwrap_or_default(),
            minfeefilter: info.minimum_fee_filter,
            minimum_ping: info.minimum_ping.unwrap_or_default(),
            network: info.network,
            ping_time: info.ping_time.unwrap_or_default(),
            ping_wait: info.ping_wait.unwrap_or_default(),
            permissions: info.permissions,
            relay_transactions: info.relay_transactions,
            services: info.services,
            starting_height: info.starting_height.unwrap_or_default(),
            subversion: info.subversion,
            synced_blocks: info.synced_blocks.unwrap_or_default(),
            synced_headers: info.synced_headers.unwrap_or_default(),
            time_offset: info.time_offset,
            transport_protocol_type: info.transport_protocol_type,
            version: info.version,

            // temporary
            inv_to_send: info.inv_to_send.unwrap_or_default() as u64,
            cpu_load: info.cpu_load.unwrap_or_default() as f64,
        }
    }
}

impl From<GetMempoolInfo> for MempoolInfo {
    fn from(info: GetMempoolInfo) -> Self {
        MempoolInfo {
            bytes: info.bytes,
            fullrbf: info.full_rbf,
            incrementalrelayfee: info.incremental_relay_fee,
            loaded: info.loaded,
            max_mempool: info.max_mempool,
            mempoolminfee: info.mempool_min_fee,
            minrelaytxfee: info.min_relay_tx_fee,
            size: info.size,
            total_fee: info.total_fee,
            usage: info.usage,
            unbroadcastcount: info.unbroadcast_count,
            // maxdatacarriersize: info.max_datacarrier_size,
            // permitbaremultisig: info.permit_bare_multisig,
        }
    }
}

impl fmt::Display for MempoolInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MempoolInfo(size={}txn, bytes={}vB, usage={}b)",
            self.size, self.bytes, self.usage
        )
    }
}

impl From<RPCGetNetTotals> for NetTotals {
    fn from(totals: RPCGetNetTotals) -> Self {
        NetTotals {
            total_bytes_received: totals.total_bytes_received,
            total_bytes_sent: totals.total_bytes_sent,
            time_millis: totals.time_millis,
            upload_target: totals.upload_target.into(),
        }
    }
}

impl From<RPCUploadTarget> for UploadTarget {
    fn from(target: RPCUploadTarget) -> Self {
        UploadTarget {
            timeframe: target.timeframe,
            target: target.target,
            target_reached: target.target_reached,
            serve_historical_blocks: target.serve_historical_blocks,
            bytes_left_in_cycle: target.bytes_left_in_cycle,
            time_left_in_cycle: target.time_left_in_cycle,
        }
    }
}

impl fmt::Display for NetTotals {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "NetTotals(recv={}B, sent={}B)",
            self.total_bytes_received, self.total_bytes_sent
        )
    }
}

impl fmt::Display for UploadTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UploadTarget(target={}B, reached={})",
            self.target, self.target_reached
        )
    }
}

impl fmt::Display for MemoryInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MemoryInfo(used={}B, total={}B, locked={}B)",
            self.used, self.total, self.locked
        )
    }
}

impl From<RPCGetMemoryInfoStats> for MemoryInfo {
    fn from(stats: RPCGetMemoryInfoStats) -> Self {
        // GetMemoryInfoStats is a BTreeMap<String, Locked>
        // Bitcoin Core returns a map with key "locked"
        let locked = stats
            .0
            .get("locked")
            .expect("getmemoryinfo response should contain 'locked' key")
            .clone();

        MemoryInfo {
            used: locked.used,
            free: locked.free,
            total: locked.total,
            locked: locked.locked,
            chunks_used: locked.chunks_used,
            chunks_free: locked.chunks_free,
        }
    }
}

impl From<RPCGetNetworkInfo> for NetworkInfo {
    fn from(info: RPCGetNetworkInfo) -> Self {
        NetworkInfo {
            version: info.version as u32,
            subversion: info.subversion,
            protocol_version: info.protocol_version as u32,
            local_services: info.local_services,
            local_services_names: info.local_services_names,
            local_relay: info.local_relay,
            time_offset: info.time_offset as i32,
            connections: info.connections as u32,
            connections_in: info.connections_in as u32,
            connections_out: info.connections_out as u32,
            network_active: info.network_active,
            networks: info.networks.into_iter().map(|n| n.into()).collect(),
            relay_fee: info.relay_fee,
            incremental_fee: info.incremental_fee,
            local_addresses: info.local_addresses.into_iter().map(|a| a.into()).collect(),
            warnings: info.warnings.join("; "),
        }
    }
}

impl fmt::Display for AddrManInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let total: u64 = self.networks.values().map(|n| n.total).sum();
        write!(f, "AddrManInfo(total={})", total)
    }
}

impl fmt::Display for AddrManInfoNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AddrManInfoNetwork(new={}, tried={}, total={})",
            self.new, self.tried, self.total
        )
    }
}

impl From<RPCGetNetworkInfoNetwork> for NetworkInfoNetwork {
    fn from(network: RPCGetNetworkInfoNetwork) -> Self {
        NetworkInfoNetwork {
            name: network.name,
            limited: network.limited,
            reachable: network.reachable,
            proxy: network.proxy,
            proxy_randomize_credentials: network.proxy_randomize_credentials,
        }
    }
}

impl From<RPCGetNetworkInfoAddress> for NetworkInfoLocalAddress {
    fn from(address: RPCGetNetworkInfoAddress) -> Self {
        NetworkInfoLocalAddress {
            address: address.address,
            port: address.port as u32,
            score: address.score as u32,
        }
    }
}

impl fmt::Display for NetworkInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "NetworkInfo(version={}, connections={}, warnings={})",
            self.version,
            self.connections,
            if self.warnings.is_empty() {
                "none"
            } else {
                &self.warnings
            }
        )
    }
}

impl From<RPCGetAddrManInfo> for AddrManInfo {
    fn from(info: RPCGetAddrManInfo) -> Self {
        let networks = info.0.into_iter().map(|(k, v)| (k, v.into())).collect();

        AddrManInfo { networks }
    }
}

impl From<RPCAddrManInfoNetwork> for AddrManInfoNetwork {
    fn from(network: RPCAddrManInfoNetwork) -> Self {
        AddrManInfoNetwork {
            new: network.new,
            tried: network.tried,
            total: network.total,
        }
    }
}

impl fmt::Display for NetworkInfoNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Network(name={}, reachable={})",
            self.name, self.reachable
        )
    }
}

impl fmt::Display for NetworkInfoLocalAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LocalAddress({}:{})", self.address, self.port)
    }
}

impl From<RPCGetBlockchainInfo> for BlockchainInfo {
    fn from(info: RPCGetBlockchainInfo) -> Self {
        BlockchainInfo {
            chain: info.chain,
            blocks: info.blocks as u32,
            headers: info.headers as u32,
            bestblockhash: info.best_block_hash,
            difficulty: info.difficulty,
            time: info.time as u64,
            mediantime: info.median_time as u64,
            verificationprogress: info.verification_progress,
            initialblockdownload: info.initial_block_download,
            chainwork: info.chain_work,
            size_on_disk: info.size_on_disk,
            pruned: info.pruned,
            pruneheight: info.prune_height.map(|h| h as u32),
            prune_target_size: info.prune_target_size.map(|s| s as u64),
            warnings: info.warnings.join("; "),
        }
    }
}

impl fmt::Display for BlockchainInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BlockchainInfo(chain={}, blocks={}, ibd={}, warnings={})",
            self.chain,
            self.blocks,
            self.initialblockdownload,
            if self.warnings.is_empty() {
                "none"
            } else {
                &self.warnings
            }
        )
    }
}
