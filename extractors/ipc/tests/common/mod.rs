use shared::{
    bitcoind,
    log::{self, info},
    nats_util::NatsArgs,
    simple_logger::SimpleLogger,
};

use std::sync::Once;

use ipc_extractor::Args;

static INIT: Once = Once::new();

// 1 second query interval for fast tests
pub const QUERY_INTERVAL_SECONDS: u64 = 1;

pub fn setup() {
    INIT.call_once(|| {
        SimpleLogger::new()
            .with_level(log::LevelFilter::Trace)
            .init()
            .unwrap();
    });
}

pub fn make_test_args(nats_port: u16, ipc_socket_path: String) -> Args {
    Args {
        nats: NatsArgs {
            address: format!("127.0.0.1:{}", nats_port),
            username: None,
            password: None,
            password_file: None,
        },
        log_level: log::Level::Trace,
        ipc_socket_path,
        query_interval: QUERY_INTERVAL_SECONDS,
        prometheus_address: "127.0.0.1:0".to_string(),
    }
}

fn bitcoin_node_exe_path() -> String {
    if let Ok(p) = std::env::var("BITCOIN_NODE_EXE") {
        return p;
    }
    let bitcoind_path =
        std::path::PathBuf::from(bitcoind::downloaded_exe_path().expect("downloaded_exe_path"));
    bitcoind_path
        .parent()
        .and_then(|p| p.parent())
        .expect("unexpected bitcoind path layout")
        .join("libexec")
        .join("bitcoin-node")
        .to_string_lossy()
        .into_owned()
}

pub fn configure_node() -> bitcoind::BitcoinD {
    let exe_path = bitcoin_node_exe_path();
    info!("Using bitcoin-node at '{}'", exe_path);

    let mut conf = bitcoind::Conf::default();
    conf.args = vec!["-regtest", "-ipcbind=unix", "-fallbackfee=0.00001"];
    conf.view_stdout = false;
    // Disable default wallet auto-creation. Create it manually in tests requiring wallet.
    conf.wallet = None;

    bitcoind::BitcoinD::with_conf(exe_path, &conf).unwrap()
}

pub fn ipc_socket_path(node: &bitcoind::BitcoinD) -> String {
    node.workdir()
        .as_path()
        .join("regtest")
        .join("node.sock")
        .to_str()
        .unwrap()
        .into()
}
