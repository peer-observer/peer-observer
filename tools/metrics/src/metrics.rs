use shared::prometheus::{
    register_gauge_with_registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry, HistogramOpts, Opts,
    Registry,
};
use shared::prometheus::{Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec};

const NAMESPACE: &str = "peerobserver";

pub const LABEL_P2P_MSG_TYPE: &str = "message";
pub const LABEL_P2P_CONNECTION_TYPE: &str = "connection_type";
pub const LABEL_P2P_DIRECTION: &str = "direction";
pub const LABEL_P2P_SUBNET: &str = "subnet";

pub const LABEL_P2P_SERVICES: &str = "services";
pub const LABEL_P2P_ADDR_TIMESTAMP_OFFSET: &str = "timestamp_offset";
pub const LABEL_P2P_INV_TYPE: &str = "inv_type";
pub const LABEL_P2P_VERSION_USERAGENT: &str = "useragent";
pub const LABEL_P2P_FEEFILTER_FEERATE: &str = "feerate";
pub const LABEL_P2P_REJECT_REASON: &str = "rejectreason";
pub const LABEL_P2P_REJECT_COMMAND: &str = "rejectcommand";
pub const LABEL_P2P_PING_VALUE: &str = "value";

pub const LABEL_CONN_NETWORK: &str = "network";
pub const LABEL_CONN_ADDR: &str = "addr";
pub const LABEL_CONN_MISBEHAVING_MESSAGE: &str = "misbehavingmessage";
pub const LABEL_CONN_MISBEHAVING_ID: &str = "id";
pub const LABEL_ADDRMAN_NEW_INSERT_SUCCESS: &str = "inserted";
pub const LABEL_MEMPOOL_REASON: &str = "reason";

pub const LABEL_RPC_TRANSPORT_PROTOCOL_TYPE: &str = "transport_protocol_type";
pub const LABEL_RPC_NETWORK_TYPE: &str = "network";
pub const LABEL_RPC_CONNECTION_TYPE: &str = "connection_type";
pub const LABEL_RPC_PROTOCOL_VERSION: &str = "protocol_version";
pub const LABEL_RPC_ASN: &str = "ASN";

pub const LABEL_LOG_CATEGORY: &str = "category";
pub const LABEL_LOG_MUTATED_BLOCK_STATUS: &str = "status";

pub const BUCKETS_ADDR_ADDRESS_COUNT: [f64; 30] = [
    0f64, 1f64, 2f64, 3f64, 4f64, 5f64, 6f64, 7f64, 8f64, 9f64, 10f64, 15f64, 20f64, 25f64, 30f64,
    50f64, 75f64, 100f64, 150f64, 200f64, 250f64, 300f64, 400f64, 500f64, 600f64, 700f64, 800f64,
    900f64, 999f64, 1000f64,
];

pub const BUCKETS_INV_SIZE: [f64; 46] = [
    0f64, 1f64, 2f64, 3f64, 4f64, 5f64, 6f64, 7f64, 8f64, 9f64, 10f64, 15f64, 20f64, 25f64, 30f64,
    50f64, 75f64, 100f64, 150f64, 200f64, 250f64, 300f64, 400f64, 500f64, 600f64, 700f64, 800f64,
    900f64, 999f64, 1000f64, 2000f64, 3000f64, 4000f64, 5000f64, 6000f64, 7000f64, 8000f64,
    9000f64, 10_000f64, 20_000f64, 25_000f64, 30_000f64, 35_000f64, 40_000f64, 45_000f64,
    50_000f64,
];

pub const BUCKETS_ADDR_SERVICE_BITS: [f64; 64] = [
    0_f64,  // 0 NODE_NONE
    1_f64,  // 1 NODE_NETWORK
    2_f64,  // 2 NODE_GETUTXO
    3_f64,  // 4 NODE_BLOOM
    4_f64,  // 8 NODE_WITNESS
    5_f64,  // 16 NODE_XTHIN
    6_f64,  // 32
    7_f64,  // 64 NODE_COMPACT_FILTERS
    8_f64,  // 128
    9_f64,  // 256
    10_f64, // 512
    11_f64, // 1024 NODE_NETWORK_LIMITED
    12_f64, 13_f64, 14_f64, 15_f64, 16_f64, 17_f64, 18_f64, 19_f64, 20_f64, 21_f64, 22_f64, 23_f64,
    24_f64, 25_f64, 26_f64, 27_f64, 28_f64, 29_f64, 30_f64, 31_f64, 32_f64, 33_f64, 34_f64, 35_f64,
    36_f64, 37_f64, 38_f64, 39_f64, 40_f64, 41_f64, 42_f64, 43_f64, 44_f64, 45_f64, 46_f64, 47_f64,
    48_f64, 49_f64, 50_f64, 51_f64, 52_f64, 53_f64, 54_f64, 55_f64, 56_f64, 57_f64, 58_f64, 59_f64,
    60_f64, 61_f64, 62_f64, 63_f64,
];

// Buckets for addr(v2) message timestamp offset in seconds.
pub const BUCKETS_ADDR_ADDRESS_TIMESTAMP_OFFSET: [f64; 26] = [
    0f64,
    1f64,
    2f64,
    4f64,
    8f64,
    16f64,
    32f64,
    64f64,
    128f64,
    256f64,
    512f64,
    1024f64,
    2048f64,
    4096f64,
    8192f64,
    16384f64,
    32768f64,
    65536f64,
    131072f64,
    262144f64,
    524288f64,
    1048576f64,
    2097152f64,
    4194304f64,
    8388608f64,
    16777216f64,
];

macro_rules! g {
    ($name:ident, $desc:expr, $registry:expr) => {
        let $name: Gauge =
            register_gauge_with_registry!(Opts::new(stringify!($name), $desc), $registry)
                .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

macro_rules! ig {
    ($name:ident, $desc:expr, $registry:expr) => {
        let $name: IntGauge =
            register_int_gauge_with_registry!(Opts::new(stringify!($name), $desc), $registry)
                .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

macro_rules! igv {
    ($name:ident, $desc:expr, $labels:expr, $registry:expr) => {
        let $name: IntGaugeVec = register_int_gauge_vec_with_registry!(
            Opts::new(stringify!($name), $desc),
            &$labels,
            $registry
        )
        .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

macro_rules! icv {
    ($name:ident, $desc:expr, $labels:expr, $registry:expr) => {
        let $name: IntCounterVec = register_int_counter_vec_with_registry!(
            Opts::new(stringify!($name), $desc),
            &$labels,
            $registry
        )
        .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

macro_rules! ic {
    ($name:ident, $desc:expr, $registry:expr) => {
        let $name: IntCounter =
            register_int_counter_with_registry!(Opts::new(stringify!($name), $desc), $registry)
                .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

macro_rules! hv {
    ($name:ident, $desc:expr, $buckets:expr, $labels:expr, $registry:expr) => {
        let $name: HistogramVec = register_histogram_vec_with_registry!(
            HistogramOpts::new(stringify!($name), $desc).buckets($buckets.to_vec()),
            &$labels,
            $registry
        )
        .expect(concat!("Could not create metric '", stringify!($name), "'"));
    };
}

#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub runtime_start_timestamp: IntGauge,
    pub p2p_message_count: IntCounterVec,
    pub p2p_message_bytes: IntCounterVec,
    pub p2p_message_bytes_linkinglion: IntCounterVec,
    pub p2p_message_count_linkinglion: IntCounterVec,
    pub p2p_addr_addresses: HistogramVec,
    pub p2p_addr_timestamp_offset_seconds: HistogramVec,
    pub p2p_addr_services_bits: HistogramVec,
    pub p2p_addrv2_services_bits: HistogramVec,
    pub p2p_addr_services: IntCounterVec,
    pub p2p_addrv2_services: IntCounterVec,
    pub p2p_addrv2_addresses: HistogramVec,
    pub p2p_addrv2_timestamp_offset_seconds: HistogramVec,
    pub p2p_address_selfannouncements: IntCounterVec,
    pub p2p_address_subnetannouncements: IntCounterVec,
    pub p2p_addrv2_empty: IntCounterVec,
    pub p2p_ping_inbound_value: IntCounterVec,
    pub conn_inbound: IntCounter,
    pub conn_inbound_network: IntCounterVec,
    pub conn_inbound_banlist_monero: IntCounter,
    pub conn_inbound_banlist_gmax: IntCounter,
    pub conn_inbound_list_linkinglion: IntCounter,
    pub conn_inbound_tor_exit: IntCounter,
    pub conn_inbound_current: IntGauge,
    pub conn_outbound: IntCounter,
    pub conn_outbound_current: IntGauge,
    pub conn_outbound_network: IntCounterVec,
    pub conn_closed_network: IntCounterVec,
    pub conn_closed: IntCounter,
    pub conn_closed_age: IntCounter,
    pub conn_evicted_inbound: IntCounter,
    pub conn_misbehaving: IntCounterVec,
    pub conn_misbehaving_reason: IntCounterVec,
    pub p2p_inv_entries: IntCounterVec,
    pub p2p_inv_entries_histogram: HistogramVec,
    pub p2p_invs_homogeneous: IntCounterVec,
    pub p2p_invs_heterogeneous: IntCounterVec,
    pub p2p_invs_outbound_large: IntCounter,
    pub p2p_oldping_subnet: IntCounterVec,
    pub p2p_version_useragent: IntCounterVec,
    pub p2p_feefilter_feerate: IntCounterVec,
    pub p2p_reject_message: IntCounterVec,
    pub addrman_new_insert: IntCounterVec,
    pub addrman_tried_insert: IntCounter,
    pub mempool_added: IntCounter,
    pub mempool_added_vbytes: IntCounter,
    pub mempool_replaced: IntCounter,
    pub mempool_replaced_vbytes: IntCounter,
    pub mempool_rejected: IntCounterVec,
    pub mempool_removed: IntCounterVec,
    pub validation_block_connected_latest_height: IntGauge,
    pub validation_block_connected_latest_connection_time: IntGauge,
    pub validation_block_connected_latest_sigops: IntGauge,
    pub validation_block_connected_latest_inputs: IntGauge,
    pub validation_block_connected_latest_transactions: IntGauge,
    pub validation_block_connected_connection_time: IntCounter,

    // RPC-extractor
    // getpeeinfo
    pub rpc_peer_info_list_peers_gmax_ban: IntGauge,
    pub rpc_peer_info_list_peers_monero_ban: IntGauge,
    pub rpc_peer_info_list_peers_tor_exit: IntGauge,
    pub rpc_peer_info_list_peers_linkinglion: IntGauge,
    pub rpc_peer_info_list_peers_bitprojects: IntGaugeVec,
    pub rpc_peer_info_addr_ratelimited_peers: IntGauge,
    pub rpc_peer_info_addr_ratelimited_total: IntGauge,
    pub rpc_peer_info_addr_processed_total: IntGauge,
    pub rpc_peer_info_timeoffset_plus10s: IntGauge,
    pub rpc_peer_info_timeoffset_minus10s: IntGauge,
    pub rpc_peer_info_bip152_highbandwidth_to: IntGauge,
    pub rpc_peer_info_bip152_highbandwidth_from: IntGauge,
    pub rpc_peer_info_num_peers: IntGauge,
    pub rpc_peer_info_addr_relay_enabled_peers: IntGauge,
    pub rpc_peer_info_inflight_block_peers: IntGauge,
    pub rpc_peer_info_inflight_distinct_blocks_heights: IntGauge,
    pub rpc_peer_info_ping_wait_larger_5_seconds_block_peers: IntGauge,
    pub rpc_peer_info_transport_protocol_type_peers: IntGaugeVec,
    pub rpc_peer_info_network_peers: IntGaugeVec,
    pub rpc_peer_info_connection_type_peers: IntGaugeVec,
    pub rpc_peer_info_protocol_version_peers: IntGaugeVec,
    pub rpc_peer_info_asn_peers: IntGaugeVec,
    pub rpc_peer_info_ping_median: Gauge,
    pub rpc_peer_info_ping_mean: Gauge,
    pub rpc_peer_info_minping_median: Gauge,
    pub rpc_peer_info_minping_mean: Gauge,
    pub rpc_peer_info_sub1satvb_relay: IntGauge,
    pub rpc_peer_info_connection_divserity_inbound_ipv4: Gauge,
    pub rpc_peer_info_invtosend_sum: IntGauge,
    pub rpc_peer_info_invtosend_max: IntGauge,
    pub rpc_peer_info_invtosend_median: Gauge,
    pub rpc_peer_info_invtosend_mean: Gauge,
    pub rpc_peer_info_invtosend_min: IntGauge,
    // temporary: umerged PR https://github.com/bitcoin/bitcoin/pull/31672
    pub rpc_peer_info_cpuload_sum: Gauge,
    pub rpc_peer_info_cpuload_max: Gauge,
    pub rpc_peer_info_cpuload_median: Gauge,
    pub rpc_peer_info_cpuload_mean: Gauge,
    pub rpc_peer_info_cpuload_min: Gauge,

    // getmempoolinfo
    pub rpc_mempoolinfo_mempool_loaded: IntGauge,
    pub rpc_mempoolinfo_transaction_count: IntGauge,
    pub rpc_mempoolinfo_transaction_fees: Gauge,
    pub rpc_mempoolinfo_transaction_vbyte: IntGauge,
    pub rpc_mempoolinfo_memory_usage: IntGauge,
    pub rpc_mempoolinfo_memory_max: IntGauge,
    pub rpc_mempoolinfo_min_mempool_feerate: Gauge,
    pub rpc_mempoolinfo_min_relay_tx_feerate: Gauge,
    pub rpc_mempoolinfo_incremental_relay_feerate: Gauge,

    // uptime
    pub rpc_uptime: IntGauge,

    // getnettotals
    pub rpc_nettotals_total_bytes_received: IntGauge,
    pub rpc_nettotals_total_bytes_sent: IntGauge,

    // P2P-extractor
    pub p2pextractor_ping_duration_nanoseconds: IntGauge,
    pub p2pextractor_addrv2relay_addresses: IntCounterVec,
    pub p2pextractor_addrv2relay_messages: IntCounter,
    pub p2pextractor_addrv2relay_messages_10_or_less_entries: IntCounter,
    pub p2pextractor_addrv2relay_size: IntGauge,
    pub p2pextractor_invs_items: IntCounterVec,
    pub p2pextractor_invs_size: IntGauge,
    pub p2pextractor_invs_messages: IntCounter,
    pub p2pextractor_feefilter_messages: IntCounter,
    pub p2pextractor_feefilter_last: IntGauge,

    // log-extractor
    pub log_events: IntCounterVec,
    pub log_block_connected_events: IntCounter,
    pub log_block_checked_events: IntCounter,
    pub log_mutated_blocks: IntCounterVec,
}

impl Metrics {
    #[rustfmt::skip]
    pub fn new() -> Self {
        let registry = Registry::new_custom(Some(NAMESPACE.to_string()), None).expect("Could not setup prometheus metric registry");

        ig!(runtime_start_timestamp, "UNIX epoch timestamp of peer-observer metrics tool start.", registry);
        icv!(p2p_message_count, "Number of P2P network messages send or received.", [LABEL_P2P_MSG_TYPE, LABEL_P2P_CONNECTION_TYPE, LABEL_P2P_DIRECTION], registry);
        icv!(p2p_message_bytes, "Number of P2P network messages bytes send or received.", [LABEL_P2P_MSG_TYPE, LABEL_P2P_CONNECTION_TYPE, LABEL_P2P_DIRECTION], registry);
        icv!(p2p_message_bytes_linkinglion, "Number of P2P network messages bytes send or received by LinkingLion peers.", [LABEL_P2P_MSG_TYPE, LABEL_P2P_DIRECTION], registry);
        icv!(p2p_message_count_linkinglion, "Number of P2P network messages send or received by LinkingLion peers.", [LABEL_P2P_MSG_TYPE, LABEL_P2P_DIRECTION], registry);
        hv!(p2p_addr_addresses, "Histogram of the number of addresses contained in an outbound 'addr' message.", BUCKETS_ADDR_ADDRESS_COUNT, [LABEL_P2P_DIRECTION], registry);
        hv!(p2p_addr_timestamp_offset_seconds, "Histogram of the timestamp offset (in seconds) of addresses contained in an 'addr' message.", BUCKETS_ADDR_ADDRESS_TIMESTAMP_OFFSET, [LABEL_P2P_DIRECTION, LABEL_P2P_ADDR_TIMESTAMP_OFFSET], registry);
        hv!(p2p_addr_services_bits, "Histogram of the service flags (per bit) of addresses contained in an 'addr' message.", BUCKETS_ADDR_SERVICE_BITS, [LABEL_P2P_DIRECTION], registry);
        hv!(p2p_addrv2_services_bits, "Histogram of the service flags (per bit) of addresses contained in an 'addrv2' message.", BUCKETS_ADDR_SERVICE_BITS, [LABEL_P2P_DIRECTION], registry);
        icv!(p2p_addr_services, "Number of addresses with these service bits contained in an 'addr' message.", [LABEL_P2P_DIRECTION, LABEL_P2P_SERVICES], registry);
        icv!(p2p_addrv2_services, "Number of addresses with these service bits contained in an 'addrv2' message.", [LABEL_P2P_DIRECTION, LABEL_P2P_SERVICES], registry);
        hv!(p2p_addrv2_addresses, "Histogram of the number of addresses contained in an 'addrv2' message.", BUCKETS_ADDR_ADDRESS_COUNT, [LABEL_P2P_DIRECTION], registry);
        hv!(p2p_addrv2_timestamp_offset_seconds, "Histogram of the timestamp offset (in seconds) of addresses contained in an 'addrv2' message.", BUCKETS_ADDR_ADDRESS_TIMESTAMP_OFFSET, [LABEL_P2P_DIRECTION, LABEL_P2P_ADDR_TIMESTAMP_OFFSET], registry);
        icv!(p2p_address_selfannouncements, "Number addr(v2) messages entries that are self-announcements (e.g. addr(v2) entry address matches the sender address).", [LABEL_CONN_NETWORK, LABEL_P2P_DIRECTION], registry);
        icv!(p2p_address_subnetannouncements, "Number addr(v2) messages entries that are subnet-announcements (e.g. addr(v2) entry address subnet matches the sender address subnet). IPv4 and IPv6 only.", [LABEL_CONN_NETWORK, LABEL_P2P_DIRECTION], registry);
        icv!(p2p_ping_inbound_value, "Number of pings per value (0, u8, u16, u32, u64)", [LABEL_P2P_PING_VALUE], registry);
        icv!(p2p_addrv2_empty, "Number of empty addrv2 messages received and sent (by address).", [LABEL_P2P_DIRECTION, LABEL_CONN_ADDR], registry);
        ic!(conn_inbound, "Number of inbound connections.", registry);
        icv!(conn_inbound_network, "Number of inbound connections by network.", [LABEL_CONN_NETWORK], registry);
        ic!(conn_inbound_banlist_monero, "Number of inbound connections from IPs on the Monero banlist.", registry);
        ic!(conn_inbound_banlist_gmax, "Number of inbound connections from IPs on the GMax banlist.", registry);
        ic!(conn_inbound_list_linkinglion, "Number of inbound connections from IPs belonging to LinkingLion.", registry);
        ic!(conn_inbound_tor_exit, "Number of inbound connections from Tor exit nodes.", registry);
        ig!(conn_inbound_current, "Number of currently open inbound connections.", registry);
        ic!(conn_outbound, "Number of opened outbound connections.", registry);
        ig!(conn_outbound_current, "Number of currently open outbound connections.", registry);
        icv!(conn_outbound_network, "Number of opened outbound connections by network.", [LABEL_CONN_NETWORK], registry);
        icv!(conn_closed_network, "Number of closed connections by network.", [LABEL_CONN_NETWORK], registry);
        ic!(conn_closed, "Number of closed connections.", registry);
        ic!(conn_closed_age, "Age (in seconds) of closed connections. The age of each closed connection is added to the metric.", registry);
        ic!(conn_evicted_inbound, "Number of evicted inbound connections.", registry);
        icv!(conn_misbehaving, "Number of misbehaving connections.", [LABEL_CONN_MISBEHAVING_ID, LABEL_CONN_MISBEHAVING_MESSAGE], registry);
        icv!(conn_misbehaving_reason, "Occurences of misbehavior by reasons", [LABEL_CONN_MISBEHAVING_MESSAGE], registry);
        icv!(p2p_inv_entries, "Number of INV entries send and received with INV type.", [LABEL_P2P_DIRECTION, LABEL_P2P_INV_TYPE], registry);
        hv!(p2p_inv_entries_histogram, "Histogram number of entries contained in an INV message.", BUCKETS_INV_SIZE, [LABEL_P2P_DIRECTION], registry);
        icv!(p2p_invs_homogeneous, "Number of homogeneous INV entries sent and received.", [LABEL_P2P_DIRECTION], registry);
        icv!(p2p_invs_heterogeneous, "Number of heterogeneous INV entries sent and received.", [LABEL_P2P_DIRECTION], registry);
        ic!(p2p_invs_outbound_large, "Number of outbound INV messages with more than 35 entries, see https://bitcoincore.org/en/2024/10/08/disclose-large-inv-to-send/ and associated PR https://github.com/bitcoin/bitcoin/pull/27610.", registry);
        icv!(p2p_oldping_subnet, "Number of 'old' Pings (without a value) received by subnet.", [LABEL_P2P_SUBNET], registry);
        icv!(p2p_version_useragent, "Number of version messages received by user agent. Fake user agents from LinkingLion are set to 'LinkingLion'.", [LABEL_P2P_VERSION_USERAGENT], registry);
        icv!(p2p_feefilter_feerate, "Number of feefilter messages received and sent by feerate.", [LABEL_P2P_DIRECTION, LABEL_P2P_FEEFILTER_FEERATE], registry);
        icv!(p2p_reject_message, "Number of reject messages received by command and reason.", [LABEL_P2P_REJECT_COMMAND, LABEL_P2P_REJECT_REASON], registry);
        icv!(addrman_new_insert, "Number of attempted inserts into the addrman new table with their success as label.", [LABEL_ADDRMAN_NEW_INSERT_SUCCESS], registry);
        ic!(addrman_tried_insert, "Number of inserts into the addrman tried table", registry);
        ic!(mempool_added, "Number of transactions added to the mempool.", registry);
        ic!(mempool_added_vbytes, "Number of vbytes added to the mempool.", registry);
        ic!(mempool_replaced, "Number of transactions replaced in the mempool.", registry);
        ic!(mempool_replaced_vbytes, "Number of vbytes replaced in the mempool.", registry);
        icv!(mempool_rejected, "Number of rejected transactions with their rejection reason.", [LABEL_MEMPOOL_REASON], registry);
        icv!(mempool_removed, "Number of removed transactions with their removal reason.", [LABEL_MEMPOOL_REASON], registry);
        ig!(validation_block_connected_latest_height, "Last connected block height.", registry);
        ig!(validation_block_connected_latest_connection_time, "Last connected block connection time in µs", registry);
        ig!(validation_block_connected_latest_sigops, "Last connected block sigops.", registry);
        ig!(validation_block_connected_latest_inputs, "Last connected block inputs.", registry);
        ig!(validation_block_connected_latest_transactions, "Last connected block transactions.", registry);
        ic!(validation_block_connected_connection_time, "Last connected block connection time in µs", registry);

        // RPC-extractor
        // getpeerinfo
        ig!(rpc_peer_info_list_peers_gmax_ban, "Number of peers connected to us that are on the 2018 ban list by gmax.", registry);
        ig!(rpc_peer_info_list_peers_monero_ban, "Number of peers connected to us that are on the monero banlist.", registry);
        ig!(rpc_peer_info_list_peers_tor_exit, "Number of peers connected to us that are on the list of tor exit nodes.", registry);
        ig!(rpc_peer_info_list_peers_linkinglion, "Number of peers connected to us that are known LinkingLion nodes.", registry);
        igv!(rpc_peer_info_list_peers_bitprojects, "Number of in- and outbound connections to/from IPs belonging to bitprojects.", [LABEL_P2P_DIRECTION], registry);
        ig!(rpc_peer_info_addr_ratelimited_peers, "Number of peers connected to us that had at least one address rate-limited from being processed (see bitcoin/bitcoin #22387)", registry);
        ig!(rpc_peer_info_addr_ratelimited_total, "Number of addresses rate-limited across all connected peers (see bitcoin/bitcoin #22387).", registry);
        ig!(rpc_peer_info_addr_processed_total, "Number of addresses processed across all connected peers (see bitcoin/bitcoin #22387).", registry);
        ig!(rpc_peer_info_timeoffset_plus10s, "Number of peers with a time offset greater than 10s.", registry);
        ig!(rpc_peer_info_timeoffset_minus10s, "Number of peers with a time offset smaller than -10s.", registry);
        ig!(rpc_peer_info_bip152_highbandwidth_to, "Number of peers we selected as (compact blocks) high-bandwidth peer.", registry);
        ig!(rpc_peer_info_bip152_highbandwidth_from, "Number of peers that selected us as (compact blocks) high-bandwidth peer.", registry);
        ig!(rpc_peer_info_num_peers, "Number of peers we are connected to.", registry);
        ig!(rpc_peer_info_addr_relay_enabled_peers, "Number of peers we participate in addr relay with (addr_relay_enabled).", registry);
        ig!(rpc_peer_info_inflight_block_peers, "Number of peers that have inflight blocks for us.", registry);
        ig!(rpc_peer_info_inflight_distinct_blocks_heights, "Number of distinct inflight block heights that peers are sending us.", registry);
        ig!(rpc_peer_info_ping_wait_larger_5_seconds_block_peers, "Number of peers that have a ping_wait larger than 5 seconds.", registry);
        igv!(rpc_peer_info_transport_protocol_type_peers, "Number of peers by transport_protocol_type (usually v1 and v2).", [LABEL_RPC_TRANSPORT_PROTOCOL_TYPE], registry);
        igv!(rpc_peer_info_network_peers, "Number of peers by network.", [LABEL_RPC_NETWORK_TYPE], registry);
        igv!(rpc_peer_info_connection_type_peers, "Number of peers by connection_type", [LABEL_RPC_CONNECTION_TYPE], registry);
        igv!(rpc_peer_info_protocol_version_peers, "Number of peers by protocol_version", [LABEL_RPC_PROTOCOL_VERSION], registry);
        igv!(rpc_peer_info_asn_peers, "Number of peers by AS number", [LABEL_RPC_ASN], registry);
        g!(rpc_peer_info_ping_median, "Median ping (in milliseconds) of all connected peers.", registry);
        g!(rpc_peer_info_ping_mean, "Mean ping (in milliseconds) of all connected peers.", registry);
        g!(rpc_peer_info_minping_median, "Median min_ping (in milliseconds) of all connected peers.", registry);
        g!(rpc_peer_info_minping_mean, "Mean min_ping (in milliseconds) of all connected peers.", registry);
        ig!(rpc_peer_info_sub1satvb_relay, "Number of peers that relay sub-1 sat/vbyte transactions.", registry);
        g!(rpc_peer_info_connection_divserity_inbound_ipv4, "Diversity of IPv4 inbound connections by /16 (higher is better). Calculated: <number of distinct /16 IPv4 inbound connection subnets>/<number of inbound IPv4 peers>", registry);
        ig!(rpc_peer_info_invtosend_sum, "Sum of the inv-to-send values across all peers.", registry);
        ig!(rpc_peer_info_invtosend_max, "The maximum inv-to-send value a peers has.", registry);
        g!(rpc_peer_info_invtosend_median, "The median inv-to-send value across all peers that requested transactions from us (fRelay in verison set).", registry);
        g!(rpc_peer_info_invtosend_mean, "The mean inv-to-send value across all peers that requested transactions from us (fRelay in verison set).", registry);
        ig!(rpc_peer_info_invtosend_min, "The min inv-to-send value across all peers that requested transactions from us (fRelay in verison set).", registry);
        // temporary:
        g!(rpc_peer_info_cpuload_sum, "Sum of the cpu_load values across all peers.", registry);
        g!(rpc_peer_info_cpuload_max, "The maximum cpu_load value a peers has.", registry);
        g!(rpc_peer_info_cpuload_median, "The median cpu_load value across all peers.", registry);
        g!(rpc_peer_info_cpuload_mean, "The mean cpu_load value across all peers.", registry);
        g!(rpc_peer_info_cpuload_min, "The min cpu_load value across all peers.", registry);

        // getmempoolinfo
        ig!(rpc_mempoolinfo_mempool_loaded, "1 if the initial load attempt of the persisted mempool finished", registry);
        ig!(rpc_mempoolinfo_transaction_count, "Number of transactions in the mempool.", registry);
        g!(rpc_mempoolinfo_transaction_fees, "Sum of transaction fees in the mempool.", registry);
        ig!(rpc_mempoolinfo_transaction_vbyte, "Sum of all virtual transaction sizes as defined in BIP 141. Differs from actual serialized size because witness data is discounted.", registry);
        ig!(rpc_mempoolinfo_memory_usage, "Total memory usage of the mempool data structure in bytes.", registry);
        ig!(rpc_mempoolinfo_memory_max, "Max memory usage of the mempool data structure in bytes.", registry);
        g!(rpc_mempoolinfo_min_mempool_feerate, "(mempoolminfee) Minimum fee rate in BTC/kvB for tx to be accepted. Is the maximum of minrelaytxfee and minimum mempool fee", registry);
        g!(rpc_mempoolinfo_min_relay_tx_feerate, "(minrelaytxfee) Current minimum relay fee for transactions", registry);
        g!(rpc_mempoolinfo_incremental_relay_feerate, "(incrementalrelayfee) minimum fee rate increment for mempool limiting or replacement in BTC/kvB", registry);

        // uptime
        ig!(rpc_uptime, "Node uptime in seconds", registry);

        // getnettotals
        ig!(rpc_nettotals_total_bytes_received, "Total bytes received by the node", registry);
        ig!(rpc_nettotals_total_bytes_sent, "Total bytes sent by the node", registry);

        // P2P-extractor
        ig!(p2pextractor_ping_duration_nanoseconds, "The time it takes for a connected Bitcoin node to respond to a ping with a pong in nanoseconds.", registry);
        icv!(p2pextractor_addrv2relay_addresses, "The total number of addresses relayed to the p2p-extractor by the node, per network", ["network"], registry);
        ic!(p2pextractor_addrv2relay_messages, "The total number of addrv2 messages that the node sent to the p2p-extractor.", registry);
        ic!(p2pextractor_addrv2relay_messages_10_or_less_entries, "The number of addrv2 messages with 10 or less entries (only the addr from messages with 10 or less entries are relayed to peers by Bitcoin Core) that the node sent to the p2p-extractor.", registry);
        ig!(p2pextractor_addrv2relay_size, "The size of the last addrv2 message received by the p2p-extractor from the node.", registry);
        icv!(p2pextractor_invs_items, "The total number of invs annuonced to the p2p-extractor by the node, per inv type", [LABEL_P2P_INV_TYPE], registry);
        ic!(p2pextractor_invs_messages, "The total number of inv messages that the node sent to the p2p-extractor.", registry);
        ig!(p2pextractor_invs_size, "The size of the last inv message received by the p2p-extractor from the node.", registry);
        ic!(p2pextractor_feefilter_messages, "The total number of feefilter messages that the node sent to the p2p-extractor.", registry);
        ig!(p2pextractor_feefilter_last, "The value of the last feefilter received by the p2p-extractor from the node.", registry);

        // log-extractor
        icv!(log_events, "Number of log events received by category.", [LABEL_LOG_CATEGORY], registry);
        ic!(log_block_connected_events, "Number of block connected log events received.", registry);
        ic!(log_block_checked_events, "Number of block checked log events received.", registry);
        icv!(log_mutated_blocks, "Number of mutated blocks detected by status.", [LABEL_LOG_MUTATED_BLOCK_STATUS], registry);

        Self {
            registry,
            runtime_start_timestamp,
            p2p_message_count,
            p2p_message_bytes,
            p2p_message_bytes_linkinglion,
            p2p_message_count_linkinglion,
            p2p_addr_addresses,
            p2p_addr_timestamp_offset_seconds,
            p2p_addr_services_bits,
            p2p_addrv2_services_bits,
            p2p_addr_services,
            p2p_addrv2_services,
            p2p_addrv2_addresses,
            p2p_addrv2_timestamp_offset_seconds,
            p2p_address_selfannouncements,
            p2p_address_subnetannouncements,
            p2p_addrv2_empty,
            p2p_ping_inbound_value,
            conn_inbound,
            conn_inbound_network,
            conn_inbound_banlist_monero,
            conn_inbound_banlist_gmax,
            conn_inbound_list_linkinglion,
            conn_inbound_tor_exit,
            conn_inbound_current,
            conn_outbound,
            conn_outbound_current,
            conn_outbound_network,
            conn_closed_network,
            conn_closed,
            conn_closed_age,
            conn_evicted_inbound,
            conn_misbehaving,
            conn_misbehaving_reason,
            p2p_inv_entries,
            p2p_inv_entries_histogram,
            p2p_invs_homogeneous,
            p2p_invs_heterogeneous,
            p2p_invs_outbound_large,
            p2p_oldping_subnet,
            p2p_version_useragent,
            p2p_feefilter_feerate,
            p2p_reject_message,
            addrman_new_insert,
            addrman_tried_insert,
            mempool_added,
            mempool_added_vbytes,
            mempool_replaced,
            mempool_replaced_vbytes,
            mempool_rejected,
            mempool_removed,
            validation_block_connected_latest_height,
            validation_block_connected_latest_connection_time,
            validation_block_connected_latest_sigops,
            validation_block_connected_latest_inputs,
            validation_block_connected_latest_transactions,
            validation_block_connected_connection_time,

            // RPC-extractor
            // getpeerinfo
            rpc_peer_info_list_peers_gmax_ban,
            rpc_peer_info_list_peers_monero_ban,
            rpc_peer_info_list_peers_tor_exit,
            rpc_peer_info_list_peers_linkinglion,
            rpc_peer_info_list_peers_bitprojects,
            rpc_peer_info_addr_ratelimited_peers,
            rpc_peer_info_addr_ratelimited_total,
            rpc_peer_info_addr_processed_total,
            rpc_peer_info_timeoffset_plus10s,
            rpc_peer_info_timeoffset_minus10s,
            rpc_peer_info_bip152_highbandwidth_to,
            rpc_peer_info_bip152_highbandwidth_from,
            rpc_peer_info_num_peers,
            rpc_peer_info_addr_relay_enabled_peers,
            rpc_peer_info_inflight_block_peers,
            rpc_peer_info_inflight_distinct_blocks_heights,
            rpc_peer_info_ping_wait_larger_5_seconds_block_peers,
            rpc_peer_info_transport_protocol_type_peers,
            rpc_peer_info_network_peers,
            rpc_peer_info_connection_type_peers,
            rpc_peer_info_protocol_version_peers,
            rpc_peer_info_asn_peers,
            rpc_peer_info_ping_median,
            rpc_peer_info_ping_mean,
            rpc_peer_info_minping_median,
            rpc_peer_info_minping_mean,
            rpc_peer_info_sub1satvb_relay,
            rpc_peer_info_connection_divserity_inbound_ipv4,
            rpc_peer_info_invtosend_sum,
            rpc_peer_info_invtosend_max,
            rpc_peer_info_invtosend_median,
            rpc_peer_info_invtosend_mean,
            rpc_peer_info_invtosend_min,
            // temporary:
            rpc_peer_info_cpuload_sum,
            rpc_peer_info_cpuload_max,
            rpc_peer_info_cpuload_median,
            rpc_peer_info_cpuload_mean,
            rpc_peer_info_cpuload_min,

            // getmempoolinfo
            rpc_mempoolinfo_mempool_loaded,
            rpc_mempoolinfo_transaction_count,
            rpc_mempoolinfo_transaction_fees,
            rpc_mempoolinfo_transaction_vbyte,
            rpc_mempoolinfo_memory_usage,
            rpc_mempoolinfo_memory_max,
            rpc_mempoolinfo_min_mempool_feerate,
            rpc_mempoolinfo_min_relay_tx_feerate,
            rpc_mempoolinfo_incremental_relay_feerate,

            // uptime
            rpc_uptime,

            // getnettotals
            rpc_nettotals_total_bytes_received,
            rpc_nettotals_total_bytes_sent,

            // p2p-extractor
            p2pextractor_ping_duration_nanoseconds,
            p2pextractor_addrv2relay_addresses,
            p2pextractor_addrv2relay_messages,
            p2pextractor_addrv2relay_messages_10_or_less_entries,
            p2pextractor_addrv2relay_size,
            p2pextractor_invs_items,
            p2pextractor_invs_messages,
            p2pextractor_invs_size,
            p2pextractor_feefilter_messages,
            p2pextractor_feefilter_last,
            // log-extractor
            log_events,
            log_block_connected_events,
            log_block_checked_events,
            log_mutated_blocks,
        }
    }
}
