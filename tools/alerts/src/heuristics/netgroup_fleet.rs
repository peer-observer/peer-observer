//! Alerts when many inbound peers come from the same netgroup.
//!
//! Bitcoin Core picks its outbound peers from different netgroups so that no
//! single network can surround it. Inbound connections are not spread like
//! that: anyone can open many. A netgroup holding an outsized share of our
//! inbound slots is one operator running many nodes, or one party trying to
//! occupy our slots. The counts come from `getpeerinfo`, so peers connected
//! before the tool started are included. Only IPv4 and IPv6 peers are
//! grouped: onion, I2P and CJDNS peers have no address to group by, and
//! inbound Tor connections all show up as localhost. Peers on private and
//! loopback addresses are the operator's own tools.

use super::{netgroup_of, peer_infos, Context, Heuristic};
use crate::alerter::Alert;
use shared::clap;
use shared::protobuf::event::Event;
use shared::protobuf::rpc_extractor::PeerInfo;
use std::collections::{HashMap, HashSet};

pub const DEFAULT_FLEET_THRESHOLD: usize = 8;

/// Inbound peers with a public IP address to group by. `getpeerinfo` names
/// the network as ipv4, ipv6, onion, i2p, cjdns or not_publicly_routable.
fn counted(peer: &&PeerInfo) -> bool {
    peer.inbound && (peer.network == "ipv4" || peer.network == "ipv6")
}

#[derive(clap::Args, Debug, Clone)]
pub struct NetgroupFleetArgs {
    /// Number of inbound peers from one netgroup before alerting
    #[arg(long, default_value_t = DEFAULT_FLEET_THRESHOLD)]
    pub fleet_threshold: usize,
}

impl Default for NetgroupFleetArgs {
    fn default() -> Self {
        NetgroupFleetArgs {
            fleet_threshold: DEFAULT_FLEET_THRESHOLD,
        }
    }
}

pub struct NetgroupFleet {
    args: NetgroupFleetArgs,
    /// Netgroups currently reported. A group is reported again only after
    /// it dropped back to the threshold.
    reported: HashSet<String>,
}

impl NetgroupFleet {
    pub fn new(args: NetgroupFleetArgs) -> Self {
        NetgroupFleet {
            args,
            reported: HashSet::new(),
        }
    }
}

impl Heuristic for NetgroupFleet {
    fn on_event(&mut self, event: &Event, _ctx: &Context, out: &mut Vec<Alert>) {
        let Some(infos) = peer_infos(event) else {
            return;
        };
        let mut counts: HashMap<String, usize> = HashMap::new();
        for peer in infos.infos.iter().filter(counted) {
            *counts.entry(netgroup_of(&peer.address)).or_default() += 1;
        }
        self.reported.retain(|group| {
            counts
                .get(group)
                .is_some_and(|c| *c > self.args.fleet_threshold)
        });
        let inbound_total = infos.infos.iter().filter(counted).count();
        let mut groups: Vec<_> = counts
            .into_iter()
            .filter(|(group, count)| {
                *count > self.args.fleet_threshold && !self.reported.contains(group)
            })
            .collect();
        groups.sort();
        for (netgroup, connections) in groups {
            self.reported.insert(netgroup.clone());
            out.push(Alert::NetgroupFleet {
                netgroup,
                connections,
                inbound_total,
                threshold: self.args.fleet_threshold,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::{peer_info, peer_infos_event};
    use crate::heuristics::Peers;
    use shared::protobuf::rpc_extractor::PeerInfo;
    use std::time::Instant;

    fn peer_at(id: u32, inbound: bool, addr: &str) -> PeerInfo {
        let mut info = peer_info(
            id,
            if inbound {
                "inbound"
            } else {
                "outbound-full-relay"
            },
            0.0,
        );
        info.address = addr.to_string();
        info
    }

    fn local(id: u32) -> PeerInfo {
        let mut info = peer_at(id, true, "127.0.0.1:9000");
        info.network = if id.is_multiple_of(2) {
            "onion".to_string()
        } else {
            "not_publicly_routable".to_string()
        };
        info
    }

    #[test]
    fn a_crowded_netgroup_is_reported_once_until_it_shrinks() {
        let mut heuristic = NetgroupFleet::new(NetgroupFleetArgs { fleet_threshold: 2 });
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        let crowded = vec![
            peer_at(1, true, "5.5.1.1:1000"),
            peer_at(2, true, "5.5.2.2:1000"),
            peer_at(3, true, "5.5.3.3:1000"),
            // Outbound peers do not count, nor do Tor inbound and local ones
            peer_at(4, false, "5.5.4.4:8333"),
            peer_at(5, true, "9.9.9.9:1000"),
            local(6),
            local(7),
            local(8),
        ];
        heuristic.on_event(&peer_infos_event(crowded.clone()), &ctx, &mut out);
        heuristic.on_event(&peer_infos_event(crowded.clone()), &ctx, &mut out);
        assert_eq!(
            out,
            vec![Alert::NetgroupFleet {
                netgroup: "5.5.0.0/16".to_string(),
                connections: 3,
                inbound_total: 4,
                threshold: 2,
            }]
        );

        // One leaves, then comes back: reported again
        out.clear();
        heuristic.on_event(&peer_infos_event(crowded[1..].to_vec()), &ctx, &mut out);
        assert!(out.is_empty());
        heuristic.on_event(&peer_infos_event(crowded), &ctx, &mut out);
        assert_eq!(out.len(), 1);
    }
}
