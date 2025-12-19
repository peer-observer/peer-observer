#![cfg_attr(feature = "strict", deny(warnings))]
// Allow for more metric macros in metrics.rs
#![recursion_limit = "256"]

use shared::clap::Parser;
use shared::futures::StreamExt;
use shared::log::{debug, info, warn, Level};
use shared::metricserver;
use shared::prost::Message;
use shared::protobuf::bitcoin_primitives;
use shared::protobuf::{
    ebpf_extractor::{
        addrman::addrman_event,
        connection::connection_event,
        ebpf,
        mempool::mempool_event,
        message,
        message::{message_event::Msg, reject::RejectReason},
        validation::validation_event,
    },
    event::{event::PeerObserverEvent, Event},
    log_extractor::{log, Log, LogDebugCategory},
    p2p_extractor::p2p,
    rpc_extractor::rpc,
};
use shared::tokio::sync::watch;
use shared::util::{self, is_on_linkinglion_banlist};
use shared::{async_nats, clap};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;

pub mod error;
mod metrics;
mod stat_util;

const LOG_TARGET: &str = "main";

/// A peer-observer tool that produces Prometheus metrics for received events
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The NATS server address the tool should connect and subscribe to.
    #[arg(short, long, default_value = "127.0.0.1:4222")]
    nats_address: String,
    /// The metrics server address the tool should listen on.
    #[arg(short, long, default_value = "127.0.0.1:8282")]
    metrics_address: String,
    /// The log level the tool should run with. Valid log levels
    /// are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html
    #[arg(short, long, default_value_t = Level::Debug)]
    pub log_level: Level,
}

impl Args {
    pub fn new(nats_address: String, metrics_address: String, log_level: Level) -> Self {
        Self {
            nats_address,
            metrics_address,
            log_level,
        }
    }
}

/// runs the metrics tool
/// Expects that a logger has been initialized already.
pub async fn run(
    args: Args,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), error::RuntimeError> {
    info!(target: LOG_TARGET, "Starting metrics-server...",);

    let metrics = metrics::Metrics::new();

    metricserver::start(&args.metrics_address, Some(metrics.registry.clone()))?;

    debug!("Connecting to NATS-server at {}", args.nats_address.clone());
    let nc = async_nats::connect(args.nats_address.clone()).await?;
    info!("Connected to NATS-server at {}", args.nats_address);
    let mut sub = nc.subscribe("*").await?;

    metrics
        .runtime_start_timestamp
        .set(util::current_timestamp() as i64);

    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {
                if let Some(msg) = maybe_msg {
                    handle_event(msg, metrics.clone())?;
                } else {
                    break; // subscription ended
                }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            info!("metrics tool received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn handle_event(
    msg: async_nats::Message,
    metrics: metrics::Metrics,
) -> Result<(), error::RuntimeError> {
    let unwrapped = Event::decode(msg.payload)?;
    if let Some(event) = unwrapped.peer_observer_event {
        match event {
            PeerObserverEvent::EbpfExtractor(ebpf) => match ebpf.ebpf_event.unwrap() {
                ebpf::EbpfEvent::Message(msg) => {
                    handle_p2p_message(&msg, unwrapped.timestamp, metrics);
                }
                ebpf::EbpfEvent::Connection(conn) => {
                    handle_connection_event(&conn.event.unwrap(), unwrapped.timestamp, metrics);
                }
                ebpf::EbpfEvent::Addrman(addrman) => {
                    handle_addrman_event(&addrman.event.unwrap(), metrics);
                }
                ebpf::EbpfEvent::Mempool(mempool) => {
                    handle_mempool_event(&mempool.event.unwrap(), metrics);
                }
                ebpf::EbpfEvent::Validation(validation) => {
                    handle_validation_event(&validation.event.unwrap(), metrics);
                }
            },
            PeerObserverEvent::RpcExtractor(r) => {
                if let Some(e) = r.rpc_event {
                    handle_rpc_event(&e, metrics);
                }
            }
            PeerObserverEvent::P2pExtractor(p) => {
                if let Some(e) = p.p2p_event {
                    handle_p2p_extractor_event(&e, metrics);
                }
            }
            PeerObserverEvent::LogExtractor(l) => {
                handle_log_event(&l, metrics);
            }
        }
    }

    Ok(())
}

fn handle_rpc_event(e: &rpc::RpcEvent, metrics: metrics::Metrics) {
    match e {
        rpc::RpcEvent::Uptime(uptime_seconds) => {
            metrics.rpc_uptime.set(*uptime_seconds as i64);
        }
        rpc::RpcEvent::NetTotals(net_totals) => {
            metrics
                .rpc_nettotals_total_bytes_received
                .set(net_totals.total_bytes_received as i64);
            metrics
                .rpc_nettotals_total_bytes_sent
                .set(net_totals.total_bytes_sent as i64);
        }
        rpc::RpcEvent::MemoryInfo(info) => {
            metrics.rpc_memoryinfo_locked_used.set(info.used as i64);
            metrics.rpc_memoryinfo_locked_free.set(info.free as i64);
            metrics.rpc_memoryinfo_locked_total.set(info.total as i64);
            metrics.rpc_memoryinfo_locked_locked.set(info.locked as i64);
            metrics
                .rpc_memoryinfo_locked_chunks_used
                .set(info.chunks_used as i64);
            metrics
                .rpc_memoryinfo_locked_chunks_free
                .set(info.chunks_free as i64);
        }
        rpc::RpcEvent::AddrmanInfo(info) => {
            for (network, data) in &info.networks {
                metrics
                    .rpc_addrmaninfo
                    .with_label_values(&[network.as_str(), "new"])
                    .set(data.new as i64);
                metrics
                    .rpc_addrmaninfo
                    .with_label_values(&[network.as_str(), "tried"])
                    .set(data.tried as i64);
                metrics
                    .rpc_addrmaninfo
                    .with_label_values(&[network.as_str(), "total"])
                    .set(data.total as i64);
            }
        }
        rpc::RpcEvent::MempoolInfo(info) => {
            metrics
                .rpc_mempoolinfo_mempool_loaded
                .set(if info.loaded { 1 } else { 0 });
            metrics.rpc_mempoolinfo_transaction_count.set(info.size);
            metrics.rpc_mempoolinfo_transaction_fees.set(info.total_fee);
            metrics.rpc_mempoolinfo_transaction_vbyte.set(info.bytes);
            metrics.rpc_mempoolinfo_memory_usage.set(info.usage);
            metrics.rpc_mempoolinfo_memory_max.set(info.max_mempool);
            metrics
                .rpc_mempoolinfo_min_mempool_feerate
                .set(info.mempoolminfee);
            metrics
                .rpc_mempoolinfo_min_relay_tx_feerate
                .set(info.minrelaytxfee);
            metrics
                .rpc_mempoolinfo_incremental_relay_feerate
                .set(info.incrementalrelayfee);
        }
        rpc::RpcEvent::PeerInfos(info) => {
            let mut on_gmax_banlist = 0;
            let mut on_monero_banlist = 0;
            let mut on_tor_exit_list = 0;
            let mut on_linkinglion_list = 0;
            let mut on_bitprojects_list_inbound = 0;
            let mut on_bitprojects_list_outbound = 0;

            // track how many peers have a time offset > 10s and < -10s
            let mut timeoffset_plus10s = 0;
            let mut timeoffset_minus10s = 0;

            // track how many peers we consider high bandwidth compact block peers
            // and how many consider us to be a high bandwidth peer
            let mut bip152_highbandwidth_to = 0;
            let mut bip152_highbandwidth_from = 0;

            let mut addr_rate_limited_peers = 0; // number of peers that had at least one address rate limited.
            let mut addr_rate_limited_total: u64 = 0; // total number of rate-limited addresses
            let mut addr_processed_total: u64 = 0; // total number of processed addresses
            let mut addr_relay_enabled_peers = 0; // nmber of peers we participate in address relay with

            let mut pings = vec![];
            let mut min_pings = vec![];
            // Count the number of peers that have a ping_wait larger than 5 seconds.
            // These are good candidates for dropping connections due to network issues.
            let mut ping_wait_larger_5s = 0;

            let mut peers_by_transport_protocol_type: BTreeMap<&str, i64> = BTreeMap::new();
            let mut peers_by_network: BTreeMap<&str, i64> = BTreeMap::new();
            let mut peers_by_connection_type: BTreeMap<&str, i64> = BTreeMap::new();
            let mut peers_by_protocol_version: BTreeMap<u32, i64> = BTreeMap::new();
            let mut peers_by_asn: BTreeMap<u32, i64> = BTreeMap::new();

            // When we requested a block, but a peer hasn't yet sent us the block,
            // the block is considered inflight. If a peer doesn't send us a block at all,
            // it might be stalling us.
            let mut peers_with_inflight_blocks = 0;
            let mut distinct_inflight_block_heights = BTreeSet::new();

            // We keep track of the number of peers that relay sub 1 sat/vbyte transactions.
            let mut sub1satvb_relay_peers = 0;

            // Keep track of the total number of inbound IPv4 peers and
            // the number distinct /16 subnets of these peers.
            let mut ipv4_inbound_peers = 0;
            let mut ipv4_inbound_peer_slash16s = BTreeSet::new();

            let mut invtosend_values: Vec<u64> = vec![];
            let mut cpuload_values: Vec<f64> = vec![];

            for peer in info.infos.iter() {
                let ip = util::ip_from_ipport(peer.address.clone());
                if util::is_on_gmax_banlist(&ip) {
                    on_gmax_banlist += 1;
                }
                if util::is_on_monero_banlist(&ip) {
                    on_monero_banlist += 1;
                }
                if util::is_tor_exit_node(&ip) {
                    on_tor_exit_list += 1;
                }
                if util::is_on_linkinglion_banlist(&ip) {
                    on_linkinglion_list += 1;
                }
                if util::belongs_to_bitprojects(&ip) {
                    if peer.inbound {
                        on_bitprojects_list_inbound += 1;
                    } else {
                        on_bitprojects_list_outbound += 1;
                    }
                }

                if peer.addr_rate_limited > 0 {
                    addr_rate_limited_peers += 1;
                }

                addr_rate_limited_total += peer.addr_rate_limited;
                addr_processed_total += peer.addr_processed;

                if peer.addr_relay_enabled {
                    addr_relay_enabled_peers += 1;
                }

                if peer.time_offset < -10 {
                    timeoffset_minus10s += 1;
                } else if peer.time_offset > 10 {
                    timeoffset_plus10s += 1;
                }

                // Ping times are in seconds, but we want to have them as milliseconds.
                // Also, if the ping is 0, it means we don't have a ping. So don't report it.
                if peer.ping_time > 0.0 {
                    pings.push(peer.ping_time * 1000.0);
                }
                if peer.minimum_ping > 0.0 {
                    min_pings.push(peer.minimum_ping * 1000.0);
                }
                if peer.ping_wait > 5.0 {
                    ping_wait_larger_5s += 1;
                }

                if peer.bip152_hb_to {
                    bip152_highbandwidth_to += 1;
                }
                if peer.bip152_hb_from {
                    bip152_highbandwidth_from += 1;
                }

                if !peer.inflight.is_empty() {
                    peers_with_inflight_blocks += 1;
                    for inflight in peer.inflight.iter() {
                        distinct_inflight_block_heights.insert(*inflight);
                    }
                }

                peers_by_transport_protocol_type
                    .entry(&peer.transport_protocol_type)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);

                peers_by_network
                    .entry(&peer.network)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);

                peers_by_connection_type
                    .entry(&peer.connection_type)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);

                peers_by_protocol_version
                    .entry(peer.version)
                    .and_modify(|e| *e += 1)
                    .or_insert(1);

                // Not all nodes use an ASMap file and we don't care about the number
                // of non-mapped peers here. So, ignore peers mapped as 0.
                if peer.mapped_as != 0 {
                    peers_by_asn
                        .entry(peer.mapped_as)
                        .and_modify(|e| *e += 1)
                        .or_insert(1);
                }

                if peer.relay_transactions
                    // check that the minfeefilter of this pee is below 1 sat/vbyte
                    && peer.minfeefilter < 0.00001000 // in BTC/kvB (0.00001000 BTC/kvB = 1 sat/vbyte)
                    // filter out spy nodes that never request transactions
                    // and don't send transaction
                    && (peer.bytes_received_per_message.contains_key("tx")
                        || peer.bytes_sent_per_message.contains_key("tx"))
                {
                    sub1satvb_relay_peers += 1;
                }

                // To calculate the diversity of our inbound IPv4 connections,
                // we keep track of the number of peers per IPv4 /16.
                if peer.network.to_lowercase() == "ipv4" && peer.inbound {
                    let ipv4_parts = ip.split(".").collect::<Vec<&str>>();
                    if ipv4_parts.len() == 4 {
                        ipv4_inbound_peers += 1;
                        let slash16 = format!("{}-{}", ipv4_parts[0], ipv4_parts[1]);
                        ipv4_inbound_peer_slash16s.insert(slash16);
                    } else {
                        warn!(
                            "Could not split IPv4 for inbound divserity metric: ip={}",
                            ip
                        );
                    }
                }

                if peer.relay_transactions {
                    invtosend_values.push(peer.inv_to_send);
                }

                if peer.cpu_load > 0.0 {
                    cpuload_values.push(peer.cpu_load);
                }
            }

            metrics
                .rpc_peer_info_list_peers_gmax_ban
                .set(on_gmax_banlist);
            metrics
                .rpc_peer_info_list_peers_monero_ban
                .set(on_monero_banlist);
            metrics
                .rpc_peer_info_list_peers_tor_exit
                .set(on_tor_exit_list);
            metrics
                .rpc_peer_info_list_peers_linkinglion
                .set(on_linkinglion_list);
            metrics
                .rpc_peer_info_list_peers_bitprojects
                .with_label_values(&[&"inbound"])
                .set(on_bitprojects_list_inbound);
            metrics
                .rpc_peer_info_list_peers_bitprojects
                .with_label_values(&[&"outbound"])
                .set(on_bitprojects_list_outbound);

            metrics
                .rpc_peer_info_addr_ratelimited_peers
                .set(addr_rate_limited_peers);
            metrics
                .rpc_peer_info_addr_ratelimited_total
                .set(addr_rate_limited_total as i64);
            metrics
                .rpc_peer_info_addr_processed_total
                .set(addr_processed_total as i64);
            metrics
                .rpc_peer_info_addr_relay_enabled_peers
                .set(addr_relay_enabled_peers);

            metrics
                .rpc_peer_info_ping_mean
                .set(stat_util::mean_f64(&pings));
            metrics
                .rpc_peer_info_ping_median
                .set(stat_util::median_f64(&pings));
            metrics
                .rpc_peer_info_minping_mean
                .set(stat_util::mean_f64(&min_pings));
            metrics
                .rpc_peer_info_minping_median
                .set(stat_util::median_f64(&min_pings));
            metrics
                .rpc_peer_info_ping_wait_larger_5_seconds_block_peers
                .set(ping_wait_larger_5s);

            metrics
                .rpc_peer_info_timeoffset_plus10s
                .set(timeoffset_plus10s);
            metrics
                .rpc_peer_info_timeoffset_minus10s
                .set(timeoffset_minus10s);

            metrics
                .rpc_peer_info_bip152_highbandwidth_to
                .set(bip152_highbandwidth_to);
            metrics
                .rpc_peer_info_bip152_highbandwidth_from
                .set(bip152_highbandwidth_from);

            metrics.rpc_peer_info_num_peers.set(info.infos.len() as i64);

            metrics
                .rpc_peer_info_inflight_block_peers
                .set(peers_with_inflight_blocks);
            metrics
                .rpc_peer_info_inflight_distinct_blocks_heights
                .set(distinct_inflight_block_heights.len() as i64);

            metrics.rpc_peer_info_transport_protocol_type_peers.reset();
            for (k, v) in peers_by_transport_protocol_type.iter() {
                metrics
                    .rpc_peer_info_transport_protocol_type_peers
                    .with_label_values(&[k])
                    .set(*v);
            }

            metrics.rpc_peer_info_network_peers.reset();
            for (k, v) in peers_by_network.iter() {
                metrics
                    .rpc_peer_info_network_peers
                    .with_label_values(&[k])
                    .set(*v);
            }

            metrics.rpc_peer_info_connection_type_peers.reset();
            for (k, v) in peers_by_connection_type.iter() {
                metrics
                    .rpc_peer_info_connection_type_peers
                    .with_label_values(&[k])
                    .set(*v);
            }

            metrics.rpc_peer_info_protocol_version_peers.reset();
            for (k, v) in peers_by_protocol_version.iter() {
                metrics
                    .rpc_peer_info_protocol_version_peers
                    .with_label_values(&[k.to_string()])
                    .set(*v);
            }

            metrics.rpc_peer_info_asn_peers.reset();
            for (k, v) in peers_by_asn.iter() {
                metrics
                    .rpc_peer_info_asn_peers
                    .with_label_values(&[k.to_string()])
                    .set(*v);
            }

            metrics
                .rpc_peer_info_sub1satvb_relay
                .set(sub1satvb_relay_peers);

            if ipv4_inbound_peers > 0 {
                // avoid division by zero
                metrics
                    .rpc_peer_info_connection_divserity_inbound_ipv4
                    .set(ipv4_inbound_peer_slash16s.len() as f64 / ipv4_inbound_peers as f64)
            }

            if invtosend_values.len() > 0 {
                metrics
                    .rpc_peer_info_invtosend_sum
                    .set(invtosend_values.iter().sum::<u64>() as i64);
                metrics
                    .rpc_peer_info_invtosend_max
                    .set(*invtosend_values.iter().max().unwrap_or(&0) as i64);
                metrics
                    .rpc_peer_info_invtosend_min
                    .set(*invtosend_values.iter().min().unwrap_or(&0) as i64);

                let invtosend_values_f64: Vec<f64> =
                    invtosend_values.iter().map(|v| *v as f64).collect();
                metrics
                    .rpc_peer_info_invtosend_mean
                    .set(stat_util::mean_f64(&invtosend_values_f64));
                metrics
                    .rpc_peer_info_invtosend_median
                    .set(stat_util::median_f64(&invtosend_values_f64));
            }

            if cpuload_values.len() > 0 {
                let mut cpuload_values_filtered: Vec<f64> = cpuload_values
                    .iter()
                    .cloned()
                    .filter(|x| !x.is_nan())
                    .collect();
                cpuload_values_filtered.sort_by(|a, b| a.partial_cmp(b).unwrap());

                metrics
                    .rpc_peer_info_cpuload_sum
                    .set(cpuload_values_filtered.iter().sum::<f64>());
                metrics
                    .rpc_peer_info_cpuload_max
                    .set(*cpuload_values_filtered.last().unwrap_or(&0.0));
                metrics
                    .rpc_peer_info_cpuload_min
                    .set(*cpuload_values_filtered.first().unwrap_or(&0.0));
                metrics
                    .rpc_peer_info_cpuload_mean
                    .set(stat_util::mean_f64(&cpuload_values_filtered));
                metrics
                    .rpc_peer_info_cpuload_median
                    .set(stat_util::median_f64(&cpuload_values_filtered));
            }
        }
    }
}

fn handle_mempool_event(e: &mempool_event::Event, metrics: metrics::Metrics) {
    match e {
        mempool_event::Event::Added(a) => {
            metrics.mempool_added.inc();
            metrics.mempool_added_vbytes.inc_by(a.vsize as u64);
        }
        mempool_event::Event::Removed(r) => {
            metrics
                .mempool_removed
                .with_label_values(&[&r.reason])
                .inc();
        }
        mempool_event::Event::Replaced(r) => {
            metrics.mempool_replaced.inc();
            metrics
                .mempool_replaced_vbytes
                .inc_by(r.replaced_vsize as u64);
        }
        mempool_event::Event::Rejected(r) => {
            metrics
                .mempool_rejected
                .with_label_values(&[&r.reason])
                .inc();
        }
    }
}

fn handle_validation_event(e: &validation_event::Event, metrics: metrics::Metrics) {
    match e {
        validation_event::Event::BlockConnected(v) => {
            // Due to an undetected API break, 23.x and 24.x used microseconds, while
            // 25.x, 26.x, and 27.x use nanoseconds.
            // See https://github.com/bitcoin/bitcoin/pull/29877
            // Assume the tracepoint passed nanoseconds here, but we don't need the
            // nanosecond precision and already have metrics recorded as microseconds.
            let duration_microseconds = (v.connection_time / 1000) as u64;
            metrics
                .validation_block_connected_latest_height
                .set(v.height as i64);
            metrics
                .validation_block_connected_latest_connection_time
                .set(duration_microseconds as i64);
            metrics
                .validation_block_connected_connection_time
                .inc_by(duration_microseconds);
            metrics
                .validation_block_connected_latest_sigops
                .set(v.sigops);
            metrics
                .validation_block_connected_latest_inputs
                .set(v.inputs.into());
            metrics
                .validation_block_connected_latest_transactions
                .set(v.transactions);
        }
    }
}

fn handle_connection_event(
    cevent: &connection_event::Event,
    timestamp_ms: u64,
    metrics: metrics::Metrics,
) {
    match cevent {
        connection_event::Event::Inbound(i) => {
            let ip = util::ip_from_ipport(i.conn.addr.clone());
            metrics.conn_inbound.inc();
            if util::is_tor_exit_node(&ip) {
                metrics.conn_inbound_tor_exit.inc();
            }
            if util::is_on_gmax_banlist(&ip) {
                metrics.conn_inbound_banlist_gmax.inc();
            }
            if util::is_on_monero_banlist(&ip) {
                metrics.conn_inbound_banlist_monero.inc();
            }
            if util::is_on_linkinglion_banlist(&ip) {
                metrics.conn_inbound_list_linkinglion.inc();
            }
            metrics
                .conn_inbound_network
                .with_label_values(&[&i.conn.network.to_string()])
                .inc();
            metrics
                .conn_inbound_current
                .set(i.existing_connections as i64);
        }
        connection_event::Event::Outbound(o) => {
            metrics.conn_outbound.inc();
            metrics
                .conn_outbound_network
                .with_label_values(&[&o.conn.network.to_string()])
                .inc();
            metrics
                .conn_outbound_current
                .set(o.existing_connections as i64);
        }
        connection_event::Event::Closed(c) => {
            metrics.conn_closed.inc();
            metrics
                .conn_closed_age
                .inc_by(timestamp_ms / 1000 - c.time_established);
            metrics
                .conn_closed_network
                .with_label_values(&[&c.conn.network.to_string()])
                .inc();
        }
        connection_event::Event::InboundEvicted(_) => {
            metrics.conn_evicted_inbound.inc();
        }
        connection_event::Event::Misbehaving(m) => {
            metrics
                .conn_misbehaving
                .with_label_values(&[&m.id.to_string(), &m.message])
                .inc();
            metrics
                .conn_misbehaving_reason
                .with_label_values(&[&m.message])
                .inc();
        }
    }
}

fn handle_p2p_extractor_event(p2p_event: &p2p::P2pEvent, metrics: metrics::Metrics) {
    match p2p_event {
        p2p::P2pEvent::PingDuration(ping_duration) => {
            metrics
                .p2pextractor_ping_duration_nanoseconds
                .set(ping_duration.duration as i64);
        }
        p2p::P2pEvent::AddressAnnouncement(annoucement) => {
            metrics.p2pextractor_addrv2relay_messages.inc();
            if annoucement.addresses.len() <= 10 {
                metrics
                    .p2pextractor_addrv2relay_messages_10_or_less_entries
                    .inc();
            }
            metrics
                .p2pextractor_addrv2relay_size
                .set(annoucement.addresses.len() as i64);

            let mut addresses_by_network: BTreeMap<&str, u64> = BTreeMap::new();
            for addr in annoucement.addresses.iter() {
                let address = addr.address.as_ref().unwrap();
                addresses_by_network
                    .entry(address.network())
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
            }
            for (network, v) in addresses_by_network.iter() {
                metrics
                    .p2pextractor_addrv2relay_addresses
                    .with_label_values(&[&network.to_string()])
                    .inc_by(*v);
            }
        }
        p2p::P2pEvent::InventoryAnnouncement(annoucement) => {
            metrics.p2pextractor_invs_messages.inc();
            metrics
                .p2pextractor_invs_size
                .set(annoucement.inventory.len() as i64);
            let mut invs_by_type: BTreeMap<&str, u64> = BTreeMap::new();
            for item in annoucement.inventory.iter() {
                invs_by_type
                    .entry(item.inv_type())
                    .and_modify(|e| *e += 1)
                    .or_insert(1);
            }
            for (type_, v) in invs_by_type.iter() {
                metrics
                    .p2pextractor_invs_items
                    .with_label_values(&[&type_.to_string()])
                    .inc_by(*v);
            }
        }
        p2p::P2pEvent::FeefilterAnnouncement(feefilter) => {
            metrics.p2pextractor_feefilter_messages.inc();
            metrics.p2pextractor_feefilter_last.set(*feefilter);
        }
    }
}

fn handle_addrman_event(aevent: &addrman_event::Event, metrics: metrics::Metrics) {
    match aevent {
        addrman_event::Event::New(new) => {
            metrics
                .addrman_new_insert
                .with_label_values(&[&new.inserted.to_string()])
                .inc();
        }
        addrman_event::Event::Tried(_) => {
            metrics.addrman_tried_insert.inc();
        }
    }
}

fn check_self_and_subnet_announcement(
    address: bitcoin_primitives::address::Address,
    ip: &str,
    subnet: &str,
    direction: &str,
    metrics: &metrics::Metrics,
) {
    // If the sender address and address.address match, assume it's a self-announcement.
    let network = address.network();
    if address.inner() == ip {
        metrics
            .p2p_address_selfannouncements
            .with_label_values(&[&network, &direction])
            .inc();
    } else if network == "IPv4" || network == "IPv6" {
        let addr_subnet = util::subnet(address.inner());
        if addr_subnet == subnet {
            metrics
                .p2p_address_subnetannouncements
                .with_label_values(&[&network, &direction])
                .inc();
        }
    }
}

fn handle_p2p_message(msg: &message::MessageEvent, timestamp_ms: u64, metrics: metrics::Metrics) {
    let conn_type = msg.meta.conn_type.to_string();
    let direction = if msg.meta.inbound {
        "inbound".to_string()
    } else {
        "outbound".to_string()
    };
    let ip = util::ip_from_ipport(msg.meta.addr.clone());
    let subnet = util::subnet(ip.clone());
    let mut labels = HashMap::<&str, &str>::new();
    labels.insert(metrics::LABEL_P2P_MSG_TYPE, &msg.meta.command);
    labels.insert(metrics::LABEL_P2P_CONNECTION_TYPE, &conn_type);
    labels.insert(metrics::LABEL_P2P_DIRECTION, &direction);

    metrics.p2p_message_count.with(&labels).inc();
    metrics
        .p2p_message_bytes
        .with(&labels)
        .inc_by(msg.meta.size);

    if util::is_on_linkinglion_banlist(&ip) {
        let mut labels_ll = HashMap::<&str, &str>::new();
        labels_ll.insert(metrics::LABEL_P2P_MSG_TYPE, &msg.meta.command);
        labels_ll.insert(metrics::LABEL_P2P_DIRECTION, &direction);
        metrics.p2p_message_count_linkinglion.with(&labels_ll).inc();
        metrics
            .p2p_message_bytes_linkinglion
            .with(&labels_ll)
            .inc_by(msg.meta.size);
    }

    if let Some(msg_ref) = msg.msg.as_ref() {
        match msg_ref {
            Msg::Addr(addr) => {
                metrics
                    .p2p_addr_addresses
                    .with_label_values(&[&direction])
                    .observe(addr.addresses.len() as f64);
                let future_offset = metrics
                    .p2p_addr_timestamp_offset_seconds
                    .with_label_values(&[&direction, &"future".to_string()]);
                let past_offset = metrics
                    .p2p_addr_timestamp_offset_seconds
                    .with_label_values(&[&direction, &"past".to_string()]);
                for address in addr.addresses.iter() {
                    // We substract the timestamp in the address from the time we received the
                    // message. If the remaining offset is larger than or equal to zero, the address
                    // timestamp lies in the past. If the offset is smaller than zero, the address
                    // timestamp lies in the future.
                    let offset = (timestamp_ms / 1000) as i64 - address.timestamp as i64;
                    if offset >= 0 {
                        past_offset.observe(offset as f64);
                    } else {
                        future_offset.observe((offset * -1) as f64);
                    }
                    for i in metrics::BUCKETS_ADDR_SERVICE_BITS {
                        if (1 << i as u8) & address.services > 0 {
                            metrics
                                .p2p_addr_services_bits
                                .with_label_values(&[&direction])
                                .observe(i)
                        }
                    }
                    metrics
                        .p2p_addr_services
                        .with_label_values(&[&direction, &address.services.to_string()])
                        .inc();

                    check_self_and_subnet_announcement(
                        address.address.as_ref().unwrap().clone(),
                        &ip,
                        &subnet,
                        &direction,
                        &metrics,
                    );
                }
            }
            Msg::Addrv2(addrv2) => {
                metrics
                    .p2p_addrv2_addresses
                    .with_label_values(&[&direction])
                    .observe(addrv2.addresses.len() as f64);
                let future_offset = metrics
                    .p2p_addrv2_timestamp_offset_seconds
                    .with_label_values(&[&direction, &"future".to_string()]);
                let past_offset = metrics
                    .p2p_addrv2_timestamp_offset_seconds
                    .with_label_values(&[&direction, &"past".to_string()]);
                for address in addrv2.addresses.iter() {
                    // We substract the timestamp in the address from the time we received the
                    // message. If the remaining offset is larger than or equal to zero, the address
                    // timestamp lies in the past. If the offset is smaller than zero, the address
                    // timestamp lies in the future.
                    let offset = (timestamp_ms / 1000) as i64 - address.timestamp as i64;
                    if offset >= 0 {
                        past_offset.observe(offset as f64);
                    } else {
                        future_offset.observe((offset * -1) as f64);
                    }

                    for i in metrics::BUCKETS_ADDR_SERVICE_BITS {
                        if (1 << i as u8) & address.services > 0 {
                            metrics
                                .p2p_addrv2_services_bits
                                .with_label_values(&[&direction])
                                .observe(i)
                        }
                    }
                    metrics
                        .p2p_addrv2_services
                        .with_label_values(&[&direction, &address.services.to_string()])
                        .inc();

                    check_self_and_subnet_announcement(
                        address.address.as_ref().unwrap().clone(),
                        &ip,
                        &subnet,
                        &direction,
                        &metrics,
                    );
                }
            }
            Msg::Emptyaddrv2(_) => {
                metrics
                    .p2p_addrv2_empty
                    .with_label_values(&[&direction, &ip])
                    .inc();
            }
            Msg::Inv(inv) => {
                let mut count_by_invtype: HashMap<String, u64> = HashMap::new();
                for item in inv.items.iter() {
                    let count = count_by_invtype
                        .entry(String::from((*item).inv_type()))
                        .or_insert(0);
                    *count += 1;
                }
                for (inv_type, count) in &count_by_invtype {
                    metrics
                        .p2p_inv_entries
                        .with_label_values(&[&direction, inv_type])
                        .inc_by(*count);
                }
                metrics
                    .p2p_inv_entries_histogram
                    .with_label_values(&[&direction])
                    .observe(inv.items.len() as f64);
                if count_by_invtype.len() == 1 {
                    metrics
                        .p2p_invs_homogeneous
                        .with_label_values(&[&direction])
                        .inc();
                } else {
                    metrics
                        .p2p_invs_heterogeneous
                        .with_label_values(&[&direction])
                        .inc();
                }
                // Large inv-to-send, see bitcoincore.org/en/2024/10/08/disclose-large-inv-to-send/
                if direction == "outbound" {
                    let tx_count = count_by_invtype.get("Tx").unwrap_or(&0);
                    let wtx_count = count_by_invtype.get("WTx").unwrap_or(&0);
                    if (*tx_count > 35) || (*wtx_count > 35) {
                        metrics.p2p_invs_outbound_large.inc();
                    }
                }
            }
            Msg::Ping(ping) => {
                let value_range = match ping.value {
                    0 => "0",
                    1..=0xFF => "u8",
                    0x100..=0xFFFF => "u16",
                    0x10000..=0xFFFFFFFF => "u32",
                    0x10000000..=u64::MAX => "u64",
                };
                if msg.meta.inbound {
                    metrics
                        .p2p_ping_inbound_value
                        .with_label_values(&[&value_range])
                        .inc();
                }
            }
            Msg::Oldping(_) => {
                if msg.meta.inbound {
                    metrics
                        .p2p_oldping_subnet
                        .with_label_values(&[&subnet])
                        .inc();
                }
            }
            Msg::Version(v) => {
                if msg.meta.inbound {
                    // LinkingLion is using a lot of fake user agents. To reduce noise and the metric
                    // cardinality (see https://github.com/0xB10C/peer-observer/issues/239#issuecomment-3248916550),
                    // treat them as "LinkingLion".
                    // https://b10c.me/data/observations/06-linkinglion/linkinglion-user-agents.txt
                    let user_agent = match is_on_linkinglion_banlist(&ip) {
                        true => "LinkingLion",
                        false => &v.user_agent,
                    };
                    metrics
                        .p2p_version_useragent
                        .with_label_values(&[&user_agent])
                        .inc();
                }
            }
            Msg::Feefilter(f) => {
                metrics
                    .p2p_feefilter_feerate
                    .with_label_values(&[&direction, &f.fee.to_string()])
                    .inc();
            }
            Msg::Reject(r) => {
                if msg.meta.inbound {
                    let reason = match RejectReason::try_from(r.reason) {
                        Ok(r) => r.to_string(),
                        Err(_) => "unknown".to_string(),
                    };
                    metrics
                        .p2p_reject_message
                        .with_label_values(&[&r.rejected_command, &reason])
                        .inc();
                }
            }
            _ => (),
        }
    }
}

fn handle_log_event(log: &Log, metrics: metrics::Metrics) {
    let category = LogDebugCategory::try_from(log.category)
        .unwrap_or(LogDebugCategory::Unknown)
        .as_str_name()
        .to_lowercase();

    metrics.log_events.with_label_values(&[&category]).inc();

    let Some(e) = &log.log_event else { return };
    match e {
        log::LogEvent::UnknownLogMessage(_) => {}
        log::LogEvent::BlockConnectedLog(_) => {
            metrics.log_block_connected_events.inc();
        }
        log::LogEvent::BlockCheckedLog(block) => {
            metrics.log_block_checked_events.inc();

            if block.is_mutated_block() {
                metrics
                    .log_mutated_blocks
                    .with_label_values(&[&block.state])
                    .inc();
            }
        }
    }
}
