use corepc_client::types::v17::GetNetTotals as RPCGetNetTotals;
use corepc_client::types::v17::UploadTarget as RPCUploadTarget;
use corepc_client::types::v26::{
    GetMempoolInfo, GetPeerInfo as RPCGetPeerInfo, PeerInfo as RPCPeerInfo,
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

impl fmt::Display for rpc::Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            rpc::Event::PeerInfos(infos) => write!(f, "{}", infos),
            rpc::Event::MempoolInfo(info) => write!(f, "{}", info),
            rpc::Event::Uptime(seconds) => write!(f, "Uptime({}s)", seconds),
            rpc::Event::NetTotals(totals) => write!(f, "{}", totals),
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
