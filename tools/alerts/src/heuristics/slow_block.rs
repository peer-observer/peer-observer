//! Flags blocks that took Bitcoin Core unusually long to connect.
//!
//! Connecting a block means checking all its transactions and updating the
//! UTXO set. On a healthy node this takes well under a second for most blocks.
//! A block that takes much longer points at an unusual block, a slow disk, or
//! a node under load, and delays everything the node does with that block.

use super::{block_connected, Context, Heuristic};
use crate::alerter::Alert;
use shared::bitcoin::hashes::Hash;
use shared::clap;
use shared::protobuf::event::Event;

pub const DEFAULT_SLOW_BLOCK_SECS: u64 = 60;

#[derive(clap::Args, Debug, Clone)]
pub struct SlowBlockArgs {
    /// Alert when connecting a block takes longer than this many seconds
    #[arg(long, default_value_t = DEFAULT_SLOW_BLOCK_SECS)]
    pub slow_block_secs: u64,
}

impl Default for SlowBlockArgs {
    fn default() -> Self {
        SlowBlockArgs {
            slow_block_secs: DEFAULT_SLOW_BLOCK_SECS,
        }
    }
}

pub struct SlowBlock {
    args: SlowBlockArgs,
}

impl SlowBlock {
    pub fn new(args: SlowBlockArgs) -> Self {
        SlowBlock { args }
    }
}

/// Formats a block hash the way Bitcoin Core shows it. Falls back to plain
/// hex if the hash does not have the expected length.
pub fn format_block_hash(hash: &[u8]) -> String {
    match shared::bitcoin::BlockHash::from_slice(hash) {
        Ok(hash) => hash.to_string(),
        Err(_) => hash.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

impl Heuristic for SlowBlock {
    fn on_event(&mut self, event: &Event, _ctx: &Context, out: &mut Vec<Alert>) {
        let Some(block) = block_connected(event) else {
            return;
        };
        // The tracepoint reports nanoseconds.
        let connection_time_ms = block.connection_time / 1_000_000;
        if connection_time_ms <= self.args.slow_block_secs * 1000 {
            return;
        }
        out.push(Alert::SlowBlock {
            height: block.height,
            hash: format_block_hash(&block.hash),
            connection_time_ms,
            threshold_secs: self.args.slow_block_secs,
            transactions: block.transactions,
            inputs: block.inputs,
            sigops: block.sigops,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::test_util::block;
    use crate::heuristics::Peers;
    use std::time::Instant;

    fn run(heuristic: &mut SlowBlock, events: &[Event]) -> Vec<Alert> {
        let peers = Peers::new();
        let ctx = Context {
            now: Instant::now(),
            peers: &peers,
        };
        let mut out = Vec::new();
        for event in events {
            heuristic.on_event(event, &ctx, &mut out);
        }
        out
    }

    #[test]
    fn blocks_over_the_threshold_alert() {
        let mut heuristic = SlowBlock::new(SlowBlockArgs { slow_block_secs: 2 });
        let events = [
            block(100, 1_999_999_999),
            block(101, 2_000_000_000),
            block(102, 2_500_000_000),
            block(103, 61_000_000_000),
        ];
        let alerts = run(&mut heuristic, &events);
        assert_eq!(alerts.len(), 2);
        assert_eq!(
            alerts[0],
            Alert::SlowBlock {
                height: 102,
                hash: format_block_hash(&[102; 32]),
                connection_time_ms: 2500,
                threshold_secs: 2,
                transactions: 10,
                inputs: 20,
                sigops: 30,
            }
        );
        assert!(matches!(alerts[1], Alert::SlowBlock { height: 103, .. }));
    }

    #[test]
    fn block_hashes_are_shown_like_bitcoin_core_shows_them() {
        // Bitcoin Core prints hashes with the bytes reversed
        let mut hash = [0u8; 32];
        hash[0] = 0xab;
        assert_eq!(
            format_block_hash(&hash),
            "00000000000000000000000000000000000000000000000000000000000000ab"
        );
        assert_eq!(format_block_hash(&[1, 2, 3]), "010203");
    }
}
