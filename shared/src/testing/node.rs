use crate::{bitcoin::BlockHash, bitcoind, testing::REGTEST_ADDRESS};
use std::{
    thread::sleep,
    time::{Duration, Instant},
};

const POST_IBD_TIP_TIMEOUT: Duration = Duration::from_secs(120);

fn wait_for_tip_post_ibd(node: &bitcoind::Client, expected_tip: BlockHash) {
    let start = Instant::now();

    loop {
        let info = node
            .get_blockchain_info()
            .expect("failed to get blockchain info while waiting for post-IBD tip")
            .into_model()
            .expect("failed to parse blockchain info while waiting for post-IBD tip");

        if info.best_block_hash == expected_tip && !info.initial_block_download {
            node.sync_with_validation_interface_queue()
                .expect("failed to sync validation interface queue after post-IBD tip");
            return;
        }

        if start.elapsed() >= POST_IBD_TIP_TIMEOUT {
            panic!(
                "timed out waiting for node tip {expected_tip} post-IBD; \
                 last tip={}, blocks={}, headers={}, ibd={}",
                info.best_block_hash, info.blocks, info.headers, info.initial_block_download
            );
        }

        sleep(Duration::from_millis(50));
    }
}

/// Mines one block on `miner` and waits until `observer` has that block as its
/// active post-IBD tip.
pub fn mine_and_wait_for_tip(miner: &bitcoind::Client, observer: &bitcoind::Client) {
    let generated = miner
        .generate_to_address(1, &REGTEST_ADDRESS)
        .expect("failed to generate block while waiting for post-IBD tip");
    let block_hash = generated
        .into_model()
        .expect("failed to parse generated block hash")
        .0
        .into_iter()
        .next()
        .expect("generatetoaddress returned no block hashes");

    wait_for_tip_post_ibd(observer, block_hash);
}
