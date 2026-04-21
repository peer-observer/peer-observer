use bitcoin::FeeRate;

// Types that don't have a generic model type in corepc (yet).
// Once they have a model, move them down to the mtypes!
// CORE_VERSION_GREP: When updating the corepc node crate version, bump this too.
use corepc_client::client_sync::v30::FeeEstimateMode as RPCFeeEstimateMode;
use corepc_client::types::v30::{
    AddrManInfoNetwork as RPCAddrManInfoNetwork, GetAddrManInfo as RPCGetAddrManInfo,
    GetMemoryInfoStats as RPCGetMemoryInfoStats, GetNetTotals as RPCGetNetTotals,
    GetPeerInfo as RPCGetPeerInfo, GetRawAddrMan, PeerInfo as RPCPeerInfo, RawAddrManEntry,
    UploadTarget as RPCUploadTarget,
};

// Ideally, all type imports should use the generic mtype types.
use corepc_node::mtype::{
    EstimateSmartFee as RPCEstimateSmartFee, GetBlockchainInfo, GetChainTxStats, GetMempoolInfo,
    GetNetworkInfo, GetNetworkInfoAddress, GetNetworkInfoNetwork, GetOrphanTxsVerboseTwo,
    GetOrphanTxsVerboseTwoEntry,
};

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;

pub trait FeeRateExt {
    fn to_sat_per_vb_f64(self) -> f64;
}

impl FeeRateExt for bitcoin::FeeRate {
    fn to_sat_per_vb_f64(self) -> f64 {
        self.to_sat_per_kwu() as f64 / (1000.0 / 4.0)
    }
}

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
            rpc::RpcEvent::ChainTxStats(stats) => write!(f, "{}", stats),
            rpc::RpcEvent::NetworkInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::BlockchainInfo(info) => write!(f, "{}", info),
            rpc::RpcEvent::OrphanTxs(orphans) => write!(f, "{}", orphans),
            rpc::RpcEvent::Addrman(addrman) => write!(f, "{}", addrman),
            rpc::RpcEvent::EstimateSmartFee(fee) => write!(f, "{}", fee),
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
            bytes: info.bytes as i64,
            fullrbf: info.full_rbf.unwrap_or_default(),
            incrementalrelayfee: info
                .incremental_relay_fee
                .unwrap_or(FeeRate::ZERO)
                .to_sat_per_vb_f64(),
            loaded: info.loaded.unwrap_or_default(),
            max_mempool: info.max_mempool as i64,
            mempoolminfee: info
                .mempool_min_fee
                .unwrap_or(FeeRate::ZERO)
                .to_sat_per_vb_f64(),
            minrelaytxfee: info
                .min_relay_tx_fee
                .unwrap_or(FeeRate::ZERO)
                .to_sat_per_vb_f64(),
            size: info.size as i64,
            total_fee: info.total_fee.unwrap_or_default(),
            usage: info.usage as i64,
            unbroadcastcount: info.unbroadcast_count.unwrap_or_default() as i64,
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

impl From<GetNetworkInfo> for NetworkInfo {
    fn from(info: GetNetworkInfo) -> Self {
        NetworkInfo {
            version: info.version as i32,
            subversion: info.subversion,
            protocol_version: info.protocol_version as i32,
            local_services: info.local_services,
            local_services_names: info.local_services_names.unwrap_or_default(),
            local_relay: info.local_relay,
            time_offset: info.time_offset as i32,
            connections: info.connections as u32,
            connections_in: info.connections_in.unwrap_or_default() as u32,
            connections_out: info.connections_out.unwrap_or_default() as u32,
            network_active: info.network_active,
            networks: info.networks.into_iter().map(|n| n.into()).collect(),
            relay_fee: info.relay_fee.unwrap_or(FeeRate::ZERO).to_sat_per_vb_f64(),
            incremental_fee: info
                .incremental_fee
                .unwrap_or(FeeRate::ZERO)
                .to_sat_per_vb_f64(),
            local_addresses: info.local_addresses.into_iter().map(|a| a.into()).collect(),
            warnings: info.warnings,
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

impl From<GetNetworkInfoNetwork> for NetworkInfoNetwork {
    fn from(network: GetNetworkInfoNetwork) -> Self {
        NetworkInfoNetwork {
            name: network.name,
            limited: network.limited,
            reachable: network.reachable,
            proxy: network.proxy,
            proxy_randomize_credentials: network.proxy_randomize_credentials,
        }
    }
}

impl From<GetNetworkInfoAddress> for NetworkInfoLocalAddress {
    fn from(address: GetNetworkInfoAddress) -> Self {
        NetworkInfoLocalAddress {
            address: address.address,
            port: address.port as u32,
            score: address.score,
        }
    }
}

impl fmt::Display for NetworkInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let warnings_display = if self.warnings.is_empty() {
            "none".to_string()
        } else {
            format!("[{}]", self.warnings.join("; "))
        };
        write!(
            f,
            "NetworkInfo(version={}, connections={}, warnings={})",
            self.version, self.connections, warnings_display
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

impl From<GetChainTxStats> for ChainTxStats {
    fn from(stats: GetChainTxStats) -> Self {
        ChainTxStats {
            time: stats.time,
            tx_count: stats.tx_count,
            window_final_block_hash: stats.window_final_block_hash.to_string(),
            window_final_block_height: stats.window_final_block_height.unwrap_or_default(),
            window_block_count: stats.window_block_count,
            window_tx_count: stats.window_tx_count,
            window_interval: stats.window_interval,
            tx_rate: stats.tx_rate,
        }
    }
}

impl fmt::Display for ChainTxStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChainTxStats(tx_count={}, tx_rate={:?})",
            self.tx_count, self.tx_rate
        )
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

impl From<GetBlockchainInfo> for BlockchainInfo {
    fn from(info: GetBlockchainInfo) -> Self {
        BlockchainInfo {
            chain: info.chain.to_string(),
            blocks: info.blocks,
            headers: info.headers,
            bestblockhash: info.best_block_hash.to_string(),
            difficulty: info.difficulty,
            time: info.time.unwrap_or_default(),
            mediantime: info.median_time,
            verificationprogress: info.verification_progress,
            initialblockdownload: info.initial_block_download,
            chainwork: info.chain_work.to_string(),
            size_on_disk: info.size_on_disk,
            pruned: info.pruned,
            prune_height: info.prune_height.unwrap_or_default(),
            prune_target_size: info.prune_target_size.map(|s| s as u64).unwrap_or_default(),
            warnings: info.warnings,
        }
    }
}

impl fmt::Display for BlockchainInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let warnings_display = if self.warnings.is_empty() {
            "none".to_string()
        } else {
            format!("[{}]", self.warnings.join("; "))
        };
        write!(
            f,
            "BlockchainInfo(chain={}, blocks={}, ibd={}, warnings={})",
            self.chain, self.blocks, self.initialblockdownload, warnings_display
        )
    }
}

impl fmt::Display for OrphanTxs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let txs_strs: Vec<String> = self.orphans.iter().map(|i| i.to_string()).collect();
        write!(f, "OrphanTxs([{}])", txs_strs.join(", "))
    }
}

impl fmt::Display for OrphanTx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "OrphanTx(txid={}, bytes={}, vsize={}, weight={}, from={:?})",
            self.txid, self.bytes, self.vsize, self.weight, self.from,
        )
    }
}

impl From<GetOrphanTxsVerboseTwoEntry> for OrphanTx {
    fn from(orphan: GetOrphanTxsVerboseTwoEntry) -> Self {
        OrphanTx {
            txid: orphan.txid.to_string(),
            wtxid: orphan.wtxid.to_string(),
            bytes: orphan.bytes,
            vsize: orphan.vsize,
            weight: orphan.weight,
            from: orphan.from,
            transaction: orphan.transaction.into(),
        }
    }
}

impl From<GetOrphanTxsVerboseTwo> for OrphanTxs {
    fn from(orphans: GetOrphanTxsVerboseTwo) -> Self {
        OrphanTxs {
            orphans: orphans.0.iter().map(|i| i.clone().into()).collect(),
        }
    }
}

impl fmt::Display for Addrman {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Addrman(new={}, tried={})",
            self.new
                .iter()
                .fold(0, |acc, bucket| acc + bucket.1.entries.len()),
            self.tried
                .iter()
                .fold(0, |acc, bucket| acc + bucket.1.entries.len())
        )
    }
}

impl fmt::Display for AddrmanBucket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AddrmanBucket(entries={})", self.entries.len(),)
    }
}

impl fmt::Display for AddrmanEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "AddrmanEntry({}:{}, services={}, source={})",
            self.address, self.port, self.services, self.source,
        )
    }
}

impl From<RawAddrManEntry> for AddrmanEntry {
    fn from(entry: RawAddrManEntry) -> Self {
        AddrmanEntry {
            address: entry.address,
            port: entry.port as u32, // protobuf doesn't have u16
            network: entry.network,
            services: entry.services,
            time: entry.time,
            source: entry.source,
            source_network: entry.source_network,
            mapped_as: entry.mapped_as,
            source_mapped_as: entry.source_mapped_as,
        }
    }
}

impl From<GetRawAddrMan> for Addrman {
    fn from(addrman: GetRawAddrMan) -> Self {
        fn table_to_addrman_buckets(
            in_table: &BTreeMap<String, RawAddrManEntry>,
        ) -> HashMap<u32, AddrmanBucket> {
            let mut table: HashMap<u32, AddrmanBucket> = HashMap::new();
            for (key, value) in in_table.iter() {
                let (bucket_str, pos_str) = key
                    .split_once('/')
                    .expect("addrman key must be in the form bucket/position");

                let bucket: u32 = bucket_str.parse().unwrap_or_else(|e| {
                    panic!(
                        "addrman bucket '{}' should be parsable as u32: {}",
                        bucket_str, e
                    )
                });

                let position: u32 = pos_str.parse().unwrap_or_else(|e| {
                    panic!(
                        "addrman position '{}' should be parsable as u32: {}",
                        pos_str, e
                    )
                });

                table
                    .entry(bucket)
                    .or_insert_with(|| AddrmanBucket {
                        entries: HashMap::new(),
                    })
                    .entries
                    .entry(position)
                    .or_insert_with(|| value.clone().into());
            }
            table
        }

        Addrman {
            new: table_to_addrman_buckets(&addrman.new),
            tried: table_to_addrman_buckets(&addrman.tried),
        }
    }
}

impl fmt::Display for EstimateSmartFee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = FeeEstimateMode::try_from(self.mode)
            .expect("Estimate mode must be a valid FeeEstimateMode enum variant");

        let Some(fee_rate) = self.fee_rate else {
            return write!(
                f,
                "EstimateSmartFee(estimation failed, blocks={}, mode={}, errors={:?})",
                self.blocks, mode, self.errors
            );
        };

        write!(
            f,
            "EstimateSmartFee(fee_rate={}sat/vB, blocks={}, mode={})",
            fee_rate, self.blocks, mode,
        )
    }
}

impl fmt::Display for FeeEstimateMode {
    fn fmt(&self, estimate: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(estimate, "{}", self.as_str_name())
    }
}

impl From<RPCFeeEstimateMode> for FeeEstimateMode {
    fn from(mode: RPCFeeEstimateMode) -> Self {
        match mode {
            RPCFeeEstimateMode::Unset => FeeEstimateMode::Unset,
            RPCFeeEstimateMode::Economical => FeeEstimateMode::Economical,
            RPCFeeEstimateMode::Conservative => FeeEstimateMode::Conservative,
        }
    }
}

impl EstimateSmartFee {
    pub fn from_rpc(estimate: RPCEstimateSmartFee, target: u32, mode: FeeEstimateMode) -> Self {
        let fee_rate_sat_per_vb = estimate
            .fee_rate
            .map(|fee_rate_btc_per_kvb| fee_rate_btc_per_kvb.to_sat_per_vb_f64());

        EstimateSmartFee {
            fee_rate: fee_rate_sat_per_vb,
            blocks: estimate.blocks,
            errors: estimate.errors.unwrap_or_default(),
            requested_blocks: target,
            mode: mode.into(),
        }
    }
}
